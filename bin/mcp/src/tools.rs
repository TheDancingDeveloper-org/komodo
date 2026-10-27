//! The MCP tools. Every tool returns a JSON value that the dispatcher scrubs
//! with the per-call [`Scrubber`] before it leaves the process.

use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex as StdMutex},
  time::Duration,
};

use tokio::sync::Mutex;

use anyhow::{Context, anyhow, bail};
use komodo_client::entities::{
  Operation, SystemCommand,
  stack::_PartialStackConfig,
  stack::Stack,
  update::{Log, Update, UpdateStatus},
};
use names_diff::{
  EnvChange, EnvDiff, EnvSpan, NamedValue, ValueRef, diff_env,
  diff_file, diff_resource_toml, env_spans, environment_assignment,
  environment_from_toml, fingerprint, normalize_value, parse_env,
  reference_of,
};
use serde_json::{Value, json};

use crate::{
  config::{Decision, Policy},
  komodo::{Komodo, stack_updates_query},
  redact::{
    Scrubber, env_view, project_stack, strip_html, tail, truncate,
  },
  unlock::{self, Unlock},
};

/// Log stage that carries file content in WriteStackContents updates.
const CONTENT_LOG_STAGE: &str = "File contents to write";
/// Log stage the fork's Core writes with the asserted actor.
pub const ACTOR_LOG_STAGE: &str = "Actor (asserted)";
/// Log stage the fork's Core writes with the names-only config diff.
pub const DIFF_LOG_STAGE: &str = "Config diff (names only)";

pub struct Ctx<'a> {
  pub komodo: &'a Komodo,
  pub policy: &'a Policy,
  pub scrubber: &'a Scrubber,
  /// Poll interval for deploys (shortened in tests).
  pub poll: Duration,
  /// One lock per stack id, so two calls in this process cannot interleave
  /// a read-modify-write of the same environment.
  pub env_locks: &'a EnvLocks,
  /// This MCP's own Komodo user; `None` when `GetUser` failed at startup
  /// (an older Core), in which case every unlock is refused.
  pub api_user: Option<&'a komodo_client::entities::user::User>,
  pub unlock_max_ttl: Duration,
}

/// Per-stack mutexes shared by every call on one server.
#[derive(Default)]
pub struct EnvLocks {
  inner: StdMutex<BTreeMap<String, Arc<Mutex<()>>>>,
}

impl EnvLocks {
  fn lock_for(&self, stack_id: &str) -> Arc<Mutex<()>> {
    let mut map = self.inner.lock().expect("env lock map");
    map
      .entry(stack_id.to_string())
      .or_insert_with(|| Arc::new(Mutex::new(())))
      .clone()
  }
}

/// Tool descriptors for `tools/list`.
pub fn list() -> Value {
  let stack =
    json!({"type": "string", "description": "Stack name or id"});
  let reason = json!({"type": "string", "description": "Why (stamped on the Komodo Update as X-Komodo-Reason)"});
  json!([
    {
      "name": "stack_lookup",
      "description": "Find stacks by name or id (exact match first, then substring). Empty query lists all stacks. Returns ids, server, state, repo/branch, deployed vs latest hash, services and whether this MCP may mutate the stack.",
      "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
      "annotations": {"readOnlyHint": true},
    },
    {
      "name": "get_stack",
      "description": "Get a stack's config and info with secrets redacted server-side: environment is names (+ fingerprints and [[references]]) only, file contents are fingerprints, unknown fields are withheld (default-deny).",
      "inputSchema": {"type": "object", "properties": {"stack": stack}, "required": ["stack"]},
      "annotations": {"readOnlyHint": true},
    },
    {
      "name": "env_diff",
      "description": "Names-only diff of a stack's environment against something else. `against` is ONE of: {\"stack\": other}, {\"env_file\": local path}, {\"hashes\": {NAME: fingerprint}}, {\"update\": update id (env as of that config update)}, {\"last_successful_deploy\": true} (env as of the most recent successful DeployStack). Output shows added/removed/changed names with sha256 fingerprints, never values. `before` = against, `after` = the stack now.",
      "inputSchema": {"type": "object", "properties": {"stack": stack, "against": {"type": "object"}}, "required": ["stack", "against"]},
      "annotations": {"readOnlyHint": true},
    },
    {
      "name": "read_stack_file",
      "description": "Read one of a stack's compose/config files from Komodo's cache (refreshing the cache first by default). Known env values in the content are scrubbed. Env files (.env) are refused.",
      "inputSchema": {"type": "object", "properties": {"stack": stack, "path": {"type": "string"}, "refresh": {"type": "boolean", "default": true}}, "required": ["stack", "path"]},
      "annotations": {"readOnlyHint": true},
    },
    {
      "name": "write_stack_file",
      "description": "MUTATING (allowlisted stacks only). Write a stack file (for git-backed stacks this commits to the repo). Always runs RefreshStackCache first so the change is computed against fresh content, refuses .env files, skips identical content, and re-reads afterwards to verify. Use dry_run to see the line summary without writing.",
      "inputSchema": {"type": "object", "properties": {
        "stack": stack, "path": {"type": "string"}, "content": {"type": "string"},
        "reason": reason, "dry_run": {"type": "boolean", "default": false}
      }, "required": ["stack", "path", "content"]},
      "annotations": {"destructiveHint": true},
    },
    {
      "name": "deploy_stack",
      "description": "MUTATING (allowlisted stacks only; prod requires explicit opt-in). Run DeployStack and wait server-side for the Update to complete. Returns pass/fail, the stages, and on failure the failing stage's log tail (HTML stripped, secrets scrubbed), plus container health on success. NOTE: deploying the stack your own session runs in will kill the session.",
      "inputSchema": {"type": "object", "properties": {
        "stack": stack, "services": {"type": "array", "items": {"type": "string"}},
        "reason": reason, "timeout_secs": {"type": "integer", "default": 900}
      }, "required": ["stack"]},
      "annotations": {"destructiveHint": true},
    },
    {
      "name": "edit_stack_env",
      "description": "Change one environment key on an allowlisted stack. add, replace and remove. The value must be an [[infisical://alias/env/KEY]] reference; literals are refused and never echoed. dry_run returns a names-only diff and base_fingerprint. Does not deploy.",
      "inputSchema": {"type": "object", "properties": {
        "stack": stack,
        "name": {"type": "string", "description": "Env key: ^[A-Za-z_][A-Za-z0-9_]*$"},
        "op": {"type": "string", "enum": ["add", "replace", "remove"]},
        "reference": {"type": "string", "description": "Required for add and replace. An [[infisical://alias/env/KEY]] reference."},
        "reason": reason,
        "dry_run": {"type": "boolean", "default": false},
        "if_base": {"type": "string", "description": "Whole-env fingerprint from a prior dry_run."}
      }, "required": ["stack", "name", "op", "reason"]},
      "annotations": {"destructiveHint": true},
    },
    {
      "name": "edit_stack_command",
      "description": "Append to or replace an allowlisted stack's pre_deploy or post_deploy command. Replace requires the current command fingerprint. Literal secrets are refused. The old command is never returned. Does not deploy.",
      "inputSchema": {"type": "object", "properties": {
        "stack": stack,
        "which": {"type": "string", "enum": ["pre_deploy", "post_deploy"]},
        "op": {"type": "string", "enum": ["append", "replace"]},
        "command": {"type": "string"},
        "path": {"type": "string"},
        "if_fingerprint": {"type": "string", "description": "Required for replace; fingerprint of the current command from get_stack."},
        "reason": reason,
        "dry_run": {"type": "boolean", "default": false}
      }, "required": ["stack", "which", "op", "command", "reason"]},
      "annotations": {"destructiveHint": true},
    },
    {
      "name": "container_health",
      "description": "Per-service container state and docker health check status for a stack (no env, labels or inspect dump).",
      "inputSchema": {"type": "object", "properties": {"stack": stack}, "required": ["stack"]},
      "annotations": {"readOnlyHint": true},
    },
    {
      "name": "container_logs",
      "description": "Tail one service's container log (max 1000 lines), secrets scrubbed.",
      "inputSchema": {"type": "object", "properties": {
        "stack": stack, "service": {"type": "string"},
        "tail": {"type": "integer", "default": 100}, "timestamps": {"type": "boolean", "default": false}
      }, "required": ["stack", "service"]},
      "annotations": {"readOnlyHint": true},
    },
    {
      "name": "stack_history",
      "description": "Recent Komodo Updates for a stack with who did it (user + asserted actor/reason when stamped) and what changed: names-only config/env diffs for config updates, fingerprints + line counts for file writes, pass/fail for deploys. `since_last_successful_deploy` stops at the most recent successful deploy (answers: what changed since the last good deploy, and who).",
      "inputSchema": {"type": "object", "properties": {
        "stack": stack, "limit": {"type": "integer", "default": 15},
        "since_last_successful_deploy": {"type": "boolean", "default": false}
      }, "required": ["stack"]},
      "annotations": {"readOnlyHint": true},
    },
  ])
}

fn arg_str<'a>(
  args: &'a Value,
  key: &str,
) -> anyhow::Result<&'a str> {
  args
    .get(key)
    .and_then(Value::as_str)
    .filter(|s| !s.trim().is_empty())
    .with_context(|| format!("missing string argument `{key}`"))
}

fn opt_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
  args
    .get(key)
    .and_then(Value::as_str)
    .filter(|s| !s.is_empty())
}

fn opt_bool(args: &Value, key: &str, default: bool) -> bool {
  args.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn opt_u64(args: &Value, key: &str, default: u64) -> u64 {
  args.get(key).and_then(Value::as_u64).unwrap_or(default)
}

pub async fn call(
  ctx: &Ctx<'_>,
  name: &str,
  args: &Value,
) -> anyhow::Result<Value> {
  match name {
    "stack_lookup" => stack_lookup(ctx, args).await,
    "get_stack" => get_stack(ctx, args).await,
    "env_diff" => env_diff(ctx, args).await,
    "read_stack_file" => read_stack_file(ctx, args).await,
    "write_stack_file" => write_stack_file(ctx, args).await,
    "edit_stack_env" => edit_stack_env(ctx, args).await,
    "edit_stack_command" => edit_stack_command(ctx, args).await,
    "deploy_stack" => deploy_stack(ctx, args).await,
    "container_health" => container_health(ctx, args).await,
    "container_logs" => container_logs(ctx, args).await,
    "stack_history" => stack_history(ctx, args).await,
    other => bail!("unknown tool `{other}`"),
  }
}

/// Fetch a stack and teach the scrubber its secrets before anything else
/// can be returned.
async fn fetch(ctx: &Ctx<'_>, stack: &str) -> anyhow::Result<Stack> {
  let s = ctx.komodo.get_stack(stack).await?;
  ctx.scrubber.learn_stack(&s);
  Ok(s)
}

async fn decision_json(ctx: &Ctx<'_>, name: &str) -> Value {
  match ctx.policy.decide(name) {
    Decision::Allowed => json!("allowed"),
    Decision::NotAllowlisted => {
      json!("read-only (not in KOMODO_MCP_WRITE_STACKS)")
    }
    Decision::ProtectedNeedsUnlock => match unlock::resolve_status(
      ctx.komodo,
      ctx.api_user,
      name,
      ctx.unlock_max_ttl,
    )
    .await
    {
      Ok(grant) => json!({
        "state": "unlocked",
        "until": grant.until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "scope": grant.scope,
        "by": grant.by,
        "update_id": grant.id,
      }),
      Err(error) => {
        json!({"state": "protected", "detail": error.to_string()})
      }
    },
  }
}

/// Resolve the stack (by id or name) and enforce the mutation allowlist on
/// its *resolved name*, so passing an id cannot bypass a name rule.
async fn fetch_mutable(
  ctx: &Ctx<'_>,
  stack: &str,
  scope: &str,
) -> anyhow::Result<(Stack, Option<Unlock>)> {
  let s = fetch(ctx, stack).await?;
  match ctx.policy.decide(&s.name) {
    Decision::Allowed => Ok((s, None)),
    Decision::NotAllowlisted => Err(anyhow!(
      "refused: stack `{}` is not in the mutation allowlist. This server is \
       read-only for it; add it to KOMODO_MCP_WRITE_STACKS to allow writes \
       and deploys.",
      s.name
    )),
    Decision::ProtectedNeedsUnlock => {
      let grant = unlock::resolve(
        ctx.komodo,
        ctx.api_user,
        &s.name,
        scope,
        ctx.unlock_max_ttl,
      )
      .await?;
      Ok((s, Some(grant)))
    }
  }
}

async fn stack_lookup(
  ctx: &Ctx<'_>,
  args: &Value,
) -> anyhow::Result<Value> {
  let query =
    opt_str(args, "query").unwrap_or("").trim().to_lowercase();
  let all = ctx.komodo.list_stacks().await?;
  let exact: Vec<_> = all
    .iter()
    .filter(|s| s.id == query || s.name.to_lowercase() == query)
    .collect();
  let matches: Vec<_> = if !exact.is_empty() {
    exact
  } else {
    all
      .iter()
      .filter(|s| {
        query.is_empty() || s.name.to_lowercase().contains(&query)
      })
      .collect()
  };
  let mut items = Vec::with_capacity(matches.len());
  for s in matches {
    items.push(json!({
        "id": s.id,
        "name": s.name,
        "server_id": s.info.server_id,
        "swarm_id": s.info.swarm_id,
        "state": s.info.state,
        "status": s.info.status,
        "repo": s.info.repo,
        "branch": s.info.branch,
        "linked_repo": s.info.linked_repo,
        "files_on_host": s.info.files_on_host,
        "deployed_hash": s.info.deployed_hash,
        "latest_hash": s.info.latest_hash,
        "missing_files": s.info.missing_files,
        "services": s.info.services.iter().map(|x| json!({
          "service": x.service, "image": x.image, "update_available": x.update_available
        })).collect::<Vec<_>>(),
        "mutations": decision_json(ctx, &s.name).await,
      }));
  }
  Ok(json!({ "count": items.len(), "stacks": items }))
}

async fn get_stack(
  ctx: &Ctx<'_>,
  args: &Value,
) -> anyhow::Result<Value> {
  let s = fetch(ctx, arg_str(args, "stack")?).await?;
  let mut v = project_stack(&s);
  v["mutations"] = decision_json(ctx, &s.name).await;
  Ok(v)
}

/// The env of a stack as of the newest config update before `before_ts`
/// (or the newest overall).
async fn env_as_of(
  ctx: &Ctx<'_>,
  stack_id: &str,
  before_ts: Option<i64>,
) -> anyhow::Result<(String, String)> {
  let mut q = stack_updates_query(stack_id);
  q.insert(
    "operation",
    bson::doc! { "$in": ["UpdateStack", "CreateStack"] },
  );
  if let Some(ts) = before_ts {
    q.insert("start_ts", bson::doc! { "$lt": ts });
  }
  let res = ctx.komodo.list_updates(q, 0).await?;
  let item = res.updates.first().context(
    "no config update recorded for this stack before that point, so the \
     environment at that time cannot be reconstructed",
  )?;
  let update = ctx.komodo.get_update(&item.id).await?;
  let env = environment_from_toml(&update.current_toml)
    .map_err(|e| anyhow!(e))?;
  Ok((env, update.id))
}

async fn env_diff(
  ctx: &Ctx<'_>,
  args: &Value,
) -> anyhow::Result<Value> {
  let s = fetch(ctx, arg_str(args, "stack")?).await?;
  let against = args
    .get("against")
    .and_then(Value::as_object)
    .context("missing object argument `against`")?;
  let current = &s.config.environment;
  let (label, diff) = if let Some(other) =
    against.get("stack").and_then(Value::as_str)
  {
    let o = fetch(ctx, other).await?;
    (
      format!("stack {}", o.name),
      diff_env(&o.config.environment, current),
    )
  } else if let Some(path) =
    against.get("env_file").and_then(Value::as_str)
  {
    let text = std::fs::read_to_string(path)
      .with_context(|| format!("cannot read env file {path}"))?;
    for e in parse_env(&text).entries {
      ctx.scrubber.learn(&e.name, &e.value);
    }
    (format!("file {path}"), diff_env(&text, current))
  } else if let Some(hashes) =
    against.get("hashes").and_then(Value::as_object)
  {
    // Compare fingerprints directly: map current values to fingerprints.
    let cur = parse_env(current);
    let cur_fp: BTreeMap<String, String> = cur
      .entries
      .iter()
      .map(|e| {
        (e.name.clone(), fingerprint(normalize_value(&e.value)))
      })
      .collect();
    let given: BTreeMap<String, String> = hashes
      .iter()
      .map(|(k, v)| {
        (k.clone(), v.as_str().unwrap_or_default().to_string())
      })
      .collect();
    (
      "supplied fingerprints".to_string(),
      diff_fingerprints(&given, &cur_fp),
    )
  } else if let Some(update_id) =
    against.get("update").and_then(Value::as_str)
  {
    let u = ctx.komodo.get_update(update_id).await?;
    let env = environment_from_toml(&u.current_toml)
      .map_err(|e| anyhow!(e))?;
    (format!("update {update_id}"), diff_env(&env, current))
  } else if against
    .get("last_successful_deploy")
    .and_then(Value::as_bool)
    .unwrap_or(false)
  {
    let mut q = stack_updates_query(&s.id);
    q.insert("operation", "DeployStack");
    q.insert("success", true);
    let deploys = ctx.komodo.list_updates(q, 0).await?;
    let deploy = deploys
      .updates
      .first()
      .context("no successful DeployStack recorded for this stack")?;
    let (env, update_id) =
      env_as_of(ctx, &s.id, Some(deploy.start_ts)).await?;
    (
      format!(
        "env as of the last successful deploy {} ({}), from config update {update_id}",
        deploy.id,
        ts(deploy.start_ts)
      ),
      diff_env(&env, current),
    )
  } else {
    bail!(
      "`against` must be one of {{stack}}, {{env_file}}, {{hashes}}, {{update}}, {{last_successful_deploy: true}}"
    );
  };
  Ok(json!({
    "stack": s.name,
    "before": label,
    "after": "current stack environment",
    "identical": diff.is_empty(),
    "diff": diff,
    "fingerprint_format": "sha256:<first 12 hex of sha256(value without wrapping quotes)>/<length in chars>",
  }))
}

/// Diff two name -> fingerprint maps (values are already fingerprints).
fn diff_fingerprints(
  before: &BTreeMap<String, String>,
  after: &BTreeMap<String, String>,
) -> EnvDiff {
  let r = |f: &String| ValueRef {
    fingerprint: f.clone(),
    reference: None,
  };
  let mut d = EnvDiff::default();
  for (k, a) in before {
    match after.get(k) {
      None => d.removed.push(NamedValue {
        name: k.clone(),
        value: r(a),
      }),
      Some(b) if a != b => d.changed.push(EnvChange {
        name: k.clone(),
        before: r(a),
        after: r(b),
      }),
      Some(_) => d.unchanged += 1,
    }
  }
  for (k, b) in after {
    if !before.contains_key(k) {
      d.added.push(NamedValue {
        name: k.clone(),
        value: r(b),
      });
    }
  }
  d
}

fn is_env_path(stack: &Stack, path: &str) -> bool {
  let file = path.rsplit('/').next().unwrap_or(path);
  let env_file = stack
    .config
    .env_file_path
    .rsplit('/')
    .next()
    .unwrap_or_default();
  file == ".env"
    || file.ends_with(".env")
    || file.starts_with(".env.")
    || (!env_file.is_empty() && file == env_file)
    || stack.config.additional_env_files.iter().any(|f| {
      f.path.trim_start_matches("./") == path.trim_start_matches("./")
    })
}

fn cached_file<'a>(stack: &'a Stack, path: &str) -> Option<&'a str> {
  let norm = |p: &str| p.trim_start_matches("./").to_string();
  stack
    .info
    .remote_contents
    .as_ref()?
    .iter()
    .find(|f| norm(&f.path) == norm(path))
    .map(|f| f.contents.as_str())
}

fn known_paths(stack: &Stack) -> Vec<String> {
  stack
    .info
    .remote_contents
    .iter()
    .flatten()
    .map(|f| f.path.clone())
    .collect()
}

async fn read_stack_file(
  ctx: &Ctx<'_>,
  args: &Value,
) -> anyhow::Result<Value> {
  let name = arg_str(args, "stack")?;
  let path = arg_str(args, "path")?;
  let s = fetch(ctx, name).await?;
  if is_env_path(&s, path) {
    bail!(
      "refused: `{path}` is an env file; use get_stack/env_diff for names-only views"
    );
  }
  let s = if opt_bool(args, "refresh", true) {
    ctx
      .komodo
      .refresh_cache(&s.id, Some("komodo-mcp read_stack_file"))
      .await?;
    fetch(ctx, &s.id).await?
  } else {
    s
  };
  let Some(contents) = cached_file(&s, path) else {
    if s.config.file_contents.trim().is_empty() {
      bail!(
        "`{path}` is not in the stack's cached files: {:?}",
        known_paths(&s)
      );
    }
    // UI-defined stacks keep their compose in config.file_contents.
    return Ok(json!({
      "stack": s.name, "path": "(config.file_contents)",
      "fingerprint": fingerprint(&s.config.file_contents),
      "contents": s.config.file_contents,
    }));
  };
  Ok(json!({
    "stack": s.name,
    "path": path,
    "fingerprint": fingerprint(contents),
    "lines": contents.lines().count(),
    "contents": contents,
  }))
}

fn log_stages(update: &Update) -> Vec<Value> {
  update
    .logs
    .iter()
    .filter(|l| l.stage != CONTENT_LOG_STAGE)
    .map(|l| json!({ "stage": l.stage, "success": l.success }))
    .collect()
}

/// The failing log of an update, as a clean tail.
fn failure(update: &Update, lines: usize) -> Option<Value> {
  let log: &Log = update.logs.iter().rev().find(|l| !l.success)?;
  let body = if log.stderr.trim().is_empty() {
    &log.stdout
  } else {
    &log.stderr
  };
  Some(json!({
    "stage": log.stage,
    "command": truncate(&strip_html(&log.command), 300),
    "tail": tail(&strip_html(body), lines),
  }))
}

async fn write_stack_file(
  ctx: &Ctx<'_>,
  args: &Value,
) -> anyhow::Result<Value> {
  let name = arg_str(args, "stack")?;
  let path = arg_str(args, "path")?;
  let content = args
    .get("content")
    .and_then(Value::as_str)
    .context("missing string argument `content`")?;
  let reason = opt_str(args, "reason");
  let (s, unlock) = fetch_mutable(ctx, name, "files").await?;
  let stamped = unlock::stamped_reason(unlock.as_ref(), reason);
  if is_env_path(&s, path) {
    bail!(
      "refused: `{path}` is an env file. Writing it would commit secret \
       values to the stack's repo; set env through Komodo/Infisical instead."
    );
  }
  // Refresh first: diffing against or writing over a stale cache is how
  // earlier deploys clobbered newer commits.
  ctx.komodo.refresh_cache(&s.id, stamped.as_deref()).await?;
  let s = fetch(ctx, &s.id).await?;
  let before = cached_file(&s, path);
  let change = diff_file(before, content);
  if before == Some(content) {
    return Ok(json!({
      "stack": s.name, "path": path, "changed": false,
      "note": "content identical to the freshly refreshed file; nothing written",
    }));
  }
  if opt_bool(args, "dry_run", false) {
    return Ok(json!({
      "stack": s.name, "path": path, "dry_run": true,
      "new_file": before.is_none(), "change": change,
    }));
  }
  let update = ctx
    .komodo
    .write_file(&s.id, path, content, stamped.as_deref())
    .await?;
  ctx.komodo.refresh_cache(&s.id, stamped.as_deref()).await?;
  let after = fetch(ctx, &s.id).await?;
  let verified = cached_file(&after, path) == Some(content);
  Ok(json!({
    "stack": s.name,
    "path": path,
    "changed": true,
    "new_file": before.is_none(),
    "success": update.success,
    "update_id": update.id,
    "change": change,
    "verified_after_refresh": verified,
    "latest_hash": after.info.latest_hash,
    "stages": log_stages(&update),
    "failure": failure(&update, 30),
  }))
}

fn ts(ms: i64) -> String {
  chrono::DateTime::from_timestamp_millis(ms)
    .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
    .unwrap_or_default()
}

async fn deploy_stack(
  ctx: &Ctx<'_>,
  args: &Value,
) -> anyhow::Result<Value> {
  let name = arg_str(args, "stack")?;
  let reason = opt_str(args, "reason");
  let services: Vec<String> = args
    .get("services")
    .and_then(Value::as_array)
    .map(|a| {
      a.iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect()
    })
    .unwrap_or_default();
  let timeout = Duration::from_secs(
    opt_u64(args, "timeout_secs", 900).clamp(10, 3600),
  );
  let (s, unlock) = fetch_mutable(ctx, name, "deploy").await?;
  let stamped = unlock::stamped_reason(unlock.as_ref(), reason);
  let state = ctx.komodo.action_state(&s.id).await?;
  if state.deploying
    || state.pulling
    || state.destroying
    || state.restarting
  {
    bail!("refused: stack `{}` is busy ({state:?})", s.name);
  }
  let started = ctx
    .komodo
    .deploy(&s.id, services, stamped.as_deref())
    .await?;
  if started.id.is_empty() {
    bail!("Komodo did not return an update id for the deploy");
  }
  let (update, completed) = ctx
    .komodo
    .wait_update(&started.id, timeout, ctx.poll)
    .await?;
  let pass = completed
    && update.status == UpdateStatus::Complete
    && update.success;
  let mut out = json!({
    "stack": s.name,
    "pass": pass,
    "completed": completed,
    "update_id": update.id,
    "started": ts(update.start_ts),
    "duration_secs": update.end_ts.map(|e| (e - update.start_ts) / 1000),
    "stages": log_stages(&update),
  });
  if !completed {
    out["note"] = json!(format!(
      "still running after {}s; poll stack_history or re-check later",
      timeout.as_secs()
    ));
  }
  if let Some(f) = failure(&update, 40) {
    out["failure"] = f;
  }
  if pass {
    out["health"] = health(ctx, &s.id)
      .await
      .unwrap_or_else(|e| json!({"error": format!("{e:#}")}));
  }
  Ok(out)
}

async fn health(
  ctx: &Ctx<'_>,
  stack_id: &str,
) -> anyhow::Result<Value> {
  let services = ctx.komodo.services(stack_id).await?;
  let mut items = Vec::new();
  let mut all_ok = true;
  for svc in services {
    let Some(c) = svc.container.as_ref() else {
      all_ok = false;
      items.push(json!({"service": svc.service, "image": svc.image, "container": null, "ok": false}));
      continue;
    };
    let state = serde_json::to_value(c.state).unwrap_or(Value::Null);
    let running = state.as_str() == Some("running");
    let mut h = Value::Null;
    let mut health_ok = true;
    if running
      && let Ok(inspect) =
        ctx.komodo.inspect(stack_id, &svc.service).await
    {
      // Only the health block; the inspect dump carries env and labels.
      if let Some(hh) = inspect.state.and_then(|s| s.health) {
        let status =
          serde_json::to_value(hh.status).unwrap_or(Value::Null);
        health_ok = !matches!(
          status.as_str(),
          Some("unhealthy") | Some("starting")
        );
        h = json!({
          "status": status,
          "failing_streak": hh.failing_streak,
          "last_output": hh.log.last().and_then(|l| l.output.clone()).map(|o| truncate(o.trim(), 500)),
        });
      }
    }
    let ok = running && health_ok;
    all_ok &= ok;
    items.push(json!({
      "service": svc.service,
      "container": c.name,
      "image": c.image,
      "state": state,
      "status": c.status,
      "health": h,
      "ok": ok,
    }));
  }
  Ok(json!({ "all_ok": all_ok, "services": items }))
}

async fn container_health(
  ctx: &Ctx<'_>,
  args: &Value,
) -> anyhow::Result<Value> {
  let s = fetch(ctx, arg_str(args, "stack")?).await?;
  let mut v = health(ctx, &s.id).await?;
  v["stack"] = json!(s.name);
  Ok(v)
}

async fn container_logs(
  ctx: &Ctx<'_>,
  args: &Value,
) -> anyhow::Result<Value> {
  let s = fetch(ctx, arg_str(args, "stack")?).await?;
  let service = arg_str(args, "service")?;
  let n = opt_u64(args, "tail", 100).clamp(1, 1000);
  let log = ctx
    .komodo
    .logs(&s.id, service, n, opt_bool(args, "timestamps", false))
    .await?;
  Ok(json!({
    "stack": s.name,
    "service": service,
    "success": log.success,
    "stdout": tail(&strip_html(&log.stdout), n as usize),
    "stderr": tail(&strip_html(&log.stderr), n as usize),
  }))
}

fn op_name(op: &Operation) -> String {
  serde_json::to_value(op)
    .ok()
    .and_then(|v| v.as_str().map(String::from))
    .unwrap_or_else(|| format!("{op:?}"))
}

fn actor_of(update: &Update) -> Value {
  match update.logs.iter().find(|l| l.stage == ACTOR_LOG_STAGE) {
    None => Value::Null,
    Some(l) => {
      let mut m = serde_json::Map::new();
      for line in l.stdout.lines() {
        if let Some((k, v)) = line.split_once(": ") {
          m.insert(k.trim().to_string(), json!(v.trim()));
        }
      }
      Value::Object(m)
    }
  }
}

async fn stack_history(
  ctx: &Ctx<'_>,
  args: &Value,
) -> anyhow::Result<Value> {
  let s = fetch(ctx, arg_str(args, "stack")?).await?;
  let limit = opt_u64(args, "limit", 15).clamp(1, 100) as usize;
  let since_deploy =
    opt_bool(args, "since_last_successful_deploy", false);
  let unlocks = unlock::history(ctx.komodo, &s.name).await?;
  let grant_ids: std::collections::HashSet<&str> = unlocks
    .iter()
    .filter_map(|u| u["update_id"].as_str())
    .collect();
  let mut entries = Vec::new();
  let mut page = 0;
  let mut reached_deploy = false;
  'pages: loop {
    let res = ctx
      .komodo
      .list_updates(stack_updates_query(&s.id), page)
      .await?;
    for item in res.updates {
      if entries.len() >= limit {
        break 'pages;
      }
      let op = op_name(&item.operation);
      let mut e = json!({
        "id": item.id,
        "operation": op,
        "at": ts(item.start_ts),
        "status": item.status,
        "success": item.success,
        "user": item.username,
        "operator": item.operator,
      });
      let interesting = matches!(
        item.operation,
        Operation::UpdateStack
          | Operation::CreateStack
          | Operation::RenameStack
          | Operation::WriteStackContents
      ) || !item.success
        || item.operation == Operation::DeployStack;
      if interesting {
        let u = ctx.komodo.get_update(&item.id).await?;
        e["actor"] = actor_of(&u);
        if let Some(id) = unlock::unlock_id_from_actor(&u) {
          // A reason is client-written: only an id that is one of this
          // stack's unlock grants is reported as one.
          let key = if grant_ids.contains(id.as_str()) {
            "unlock"
          } else {
            "unlock_unverified"
          };
          e[key] = json!(id);
        }
        match u.operation {
          Operation::UpdateStack | Operation::CreateStack => {
            e["config_diff"] =
              match diff_resource_toml(&u.prev_toml, &u.current_toml)
              {
                Ok(d) => {
                  serde_json::to_value(d).unwrap_or(Value::Null)
                }
                Err(err) => json!({ "error": err }),
              };
            e["core_recorded_diff"] =
              json!(u.logs.iter().any(|l| l.stage == DIFF_LOG_STAGE));
          }
          Operation::WriteStackContents => {
            if let Some(l) =
              u.logs.iter().find(|l| l.stage == CONTENT_LOG_STAGE)
            {
              e["written"] = json!({
                "fingerprint": fingerprint(&l.stdout),
                "lines": l.stdout.lines().count(),
              });
            }
            e["stages"] = json!(log_stages(&u));
          }
          _ => {
            e["stages"] = json!(log_stages(&u));
            if !u.commit_hash.is_empty() {
              e["commit_hash"] = json!(u.commit_hash);
            }
          }
        }
        if let Some(f) = failure(&u, 15) {
          e["failure"] = f;
        }
      }
      entries.push(e);
      if since_deploy
        && item.operation == Operation::DeployStack
        && item.success
      {
        reached_deploy = true;
        break 'pages;
      }
    }
    match res.next_page {
      Some(p) if entries.len() < limit => page = p,
      _ => break,
    }
  }
  Ok(json!({
    "stack": s.name,
    "count": entries.len(),
    "reached_last_successful_deploy": if since_deploy { json!(reached_deploy) } else { Value::Null },
    "updates": entries,
    "unlocks": unlocks,
    "current_environment": env_view(&s.config.environment),
  }))
}

const REFUSAL_NOT_A_REF: &str = "refused: value is not an [[infisical://alias/env/KEY]] reference; literal values cannot be set through this tool";

fn key_ok(name: &str) -> bool {
  let mut chars = name.chars();
  match chars.next() {
    Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
    _ => return false,
  }
  chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn reference_accepted(reference: &str) -> bool {
  if reference_of(reference) != Some(reference) {
    return false;
  }
  let extra =
    std::env::var("KOMODO_MCP_ENV_REF_PATTERNS").unwrap_or_default();
  let patterns: Vec<&str> = std::iter::once(
    r"^\[\[infisical://[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\]\]$",
  )
  .chain(extra.split(',').map(str::trim).filter(|s| !s.is_empty()))
  .collect();
  patterns.iter().any(|p| {
    regex::Regex::new(p)
      .map(|re| re.is_match(reference))
      .unwrap_or(false)
  })
}

/// Replace, remove or append one entry. Returns the new env, or an error
/// naming the problem (ambiguous lines, missing, already present).
fn splice_env(
  base: &str,
  name: &str,
  op: &str,
  reference: Option<&str>,
) -> anyhow::Result<String> {
  let spans: Vec<EnvSpan> = env_spans(base)
    .into_iter()
    .filter(|s| s.name == name)
    .collect();
  match op {
    "add" => {
      if !spans.is_empty() {
        bail!("refused: key {name} already exists");
      }
      let reference = reference.context("reference required")?;
      let mut out = base.to_string();
      if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
      }
      out.push_str(name);
      out.push('=');
      out.push_str(reference);
      out.push('\n');
      Ok(out)
    }
    "replace" | "remove" => {
      if spans.is_empty() {
        bail!("refused: key {name} is missing");
      }
      if spans.len() >= 2 {
        let lines = spans
          .iter()
          .map(|s| s.line.to_string())
          .collect::<Vec<_>>()
          .join(", ");
        bail!(
          "refused: ambiguous: {} entries named {name} (lines {lines})",
          spans.len()
        );
      }
      let span = &spans[0];
      let mut end = span.end;
      if op == "remove" {
        if base.as_bytes().get(end) == Some(&b'\n') {
          end += 1;
        }
        let mut start = span.start;
        // Drop the indent and `export ` / `- ` prefix that belong to this
        // entry, back to the start of the line, so the line goes away.
        if let Some(line_start) = base[..start].rfind('\n') {
          let prefix = &base[line_start + 1..start];
          if prefix.trim().is_empty()
            || prefix.trim() == "export"
            || prefix.trim() == "-"
            || prefix.trim().starts_with("- ")
          {
            start = line_start + 1;
          }
        } else if base[..start].trim().is_empty()
          || base[..start].trim() == "export"
          || base[..start].trim().starts_with('-')
        {
          start = 0;
        }
        let mut out = String::new();
        out.push_str(&base[..start]);
        out.push_str(&base[end..]);
        return Ok(out);
      }
      let reference = reference.context("reference required")?;
      let mut out = String::new();
      out.push_str(&base[..span.start]);
      out.push_str(name);
      out.push('=');
      out.push_str(reference);
      // Keep a comment that begins after the parsed value. A `#` inside
      // quotes is part of the value (`PW="abc #s3cret more"`), so it is
      // never kept. Only an unquoted trailing ` #…` is a comment.
      let line = &base[span.start..span.end];
      if !span.value.starts_with('"')
        && !span.value.starts_with('\'')
        && let Some(at) = line.find(" #")
      {
        out.push_str(&line[at..]);
      }
      out.push_str(&base[span.end..]);
      Ok(out)
    }
    other => bail!("refused: unknown op {other}"),
  }
}

fn others_fingerprints(
  env: &str,
  name: &str,
) -> BTreeMap<String, String> {
  let mut map = BTreeMap::new();
  for e in parse_env(env).entries {
    if e.name == name {
      continue;
    }
    map
      .insert(e.name.clone(), fingerprint(normalize_value(&e.value)));
  }
  map
}

fn rest_fingerprint(stack: &Stack) -> String {
  let mut v =
    serde_json::to_value(&stack.config).unwrap_or(json!({}));
  if let Some(obj) = v.as_object_mut() {
    obj.remove("environment");
  }
  fingerprint(&v.to_string())
}

fn target_before(env: &str, name: &str) -> Value {
  match parse_env(env)
    .entries
    .into_iter()
    .filter(|e| e.name == name)
    .collect::<Vec<_>>()
    .as_slice()
  {
    [one] => {
      let r = ValueRef::of(&one.value);
      json!({
        "fingerprint": r.fingerprint,
        "reference": r.reference,
        "was_literal": reference_of(&one.value).is_none(),
      })
    }
    [] => {
      json!({ "fingerprint": Value::Null, "was_literal": Value::Null })
    }
    many => json!({
      "fingerprint": Value::Null,
      "was_literal": Value::Null,
      "count": many.len(),
    }),
  }
}

async fn edit_stack_env(
  ctx: &Ctx<'_>,
  args: &Value,
) -> anyhow::Result<Value> {
  let stack_key = arg_str(args, "stack")?;
  let name = arg_str(args, "name")?;
  let op = arg_str(args, "op")?;
  let reason = arg_str(args, "reason")?;
  if reason.trim().is_empty() {
    bail!("refused: reason is required");
  }
  if !matches!(op, "add" | "replace" | "remove") {
    bail!("refused: unknown op {op}");
  }
  if !key_ok(name) {
    bail!("refused: key {name} is not ^[A-Za-z_][A-Za-z0-9_]*$");
  }
  let reference = args.get("reference").and_then(|v| v.as_str());
  if matches!(op, "add" | "replace") {
    let reference = reference.context(
      "refused: reference is required for add and replace",
    )?;
    if !reference_accepted(reference) {
      ctx.scrubber.learn(name, reference);
      bail!("{REFUSAL_NOT_A_REF}");
    }
  }
  let dry_run = opt_bool(args, "dry_run", false);
  let if_base = args.get("if_base").and_then(|v| v.as_str());

  // Gate first (existing allowlist / protected check). K3 adds Scope.
  let (stack, unlock) = fetch_mutable(ctx, stack_key, "env").await?;
  let stamped = unlock::stamped_reason(unlock.as_ref(), Some(reason));
  let guard = ctx.env_locks.lock_for(&stack.id);
  let _held = guard.lock().await;

  let state = ctx.komodo.action_state(&stack.id).await?;
  if state.deploying
    || state.pulling
    || state.destroying
    || state.restarting
  {
    bail!("refused: stack busy; retry after the current operation");
  }
  ctx
    .komodo
    .refresh_cache(&stack.id, stamped.as_deref())
    .await
    .context("RefreshStackCache failed")?;
  let stack = ctx.komodo.get_stack(&stack.id).await?;
  ctx.scrubber.learn_stack(&stack);
  let base = stack.config.environment.clone();
  let base_fp = fingerprint(&base);
  let others_before = others_fingerprints(&base, name);
  let rest_before = rest_fingerprint(&stack);

  let new_env = splice_env(&base, name, op, reference)?;
  let changed = new_env != base;
  let diff = diff_env(&base, &new_env);
  if dry_run || !changed {
    return Ok(json!({
      "stack": stack.name,
      "name": name,
      "op": op,
      "dry_run": dry_run,
      "changed": changed,
      "diff": diff,
      "base_fingerprint": base_fp,
      "target_before": target_before(&base, name),
      "unchanged": others_before.len(),
      "latest_hash": stack.info.latest_hash,
      "note": "check stack_history before deploying",
    }));
  }

  // Re-read immediately before the write.
  let again = ctx.komodo.get_stack(&stack.id).await?;
  let again_env = again.config.environment.clone();
  let again_fp = fingerprint(&again_env);
  if if_base.is_some_and(|want| want != again_fp) {
    bail!(
      "refused: if_base does not match the current environment; nothing written"
    );
  }
  if again_fp != base_fp {
    bail!(
      "conflict: environment changed since it was read; nothing written, re-run"
    );
  }

  let t0 = chrono_now_ms();
  let _written = ctx
    .komodo
    .update_stack_partial(
      &stack.id,
      _PartialStackConfig {
        environment: Some(new_env.clone()),
        ..Default::default()
      },
      stamped.as_deref(),
    )
    .await
    .context("UpdateStack failed")?;
  let update = find_env_update(ctx, &stack.id, t0).await?;
  match verify_env_write(
    ctx,
    &stack,
    name,
    &base,
    &new_env,
    &others_before,
    &rest_before,
    &update,
  )
  .await
  {
    Ok(()) => Ok(result_ok(
      &stack.name,
      name,
      op,
      &base,
      &new_env,
      &update.id,
      false,
      None,
    )),
    Err(VerifyFail::Lost { update_id }) => {
      // §5's single repair is NOT DONE (WI-2628 follow-up). A detected
      // race stops here: no second write, and `prev` (the other buffer)
      // is never stored, logged or returned. Fingerprints only.
      let _ = update_id;
      bail!(
        "error: concurrent writers; manual check needed (update {update_id})"
      );
    }
    Err(VerifyFail::Mismatch(msg)) => {
      bail!("verification failed: {msg}")
    }
  }
}

async fn edit_stack_command(
  ctx: &Ctx<'_>,
  args: &Value,
) -> anyhow::Result<Value> {
  const SECRET_REFUSAL: &str = "refused: command contains a literal secret; read it from the environment at runtime (e.g. ENVIRON in awk) or use a [[infisical://…]] interpolation";
  let stack_key = arg_str(args, "stack")?;
  let which = arg_str(args, "which")?;
  let op = arg_str(args, "op")?;
  let command = args
    .get("command")
    .and_then(Value::as_str)
    .context("missing string argument `command`")?;
  let reason = arg_str(args, "reason")?;
  if reason.trim().is_empty() {
    bail!("refused: reason is required");
  }
  if !matches!(which, "pre_deploy" | "post_deploy") {
    bail!("refused: unknown command field");
  }
  if !matches!(op, "append" | "replace") {
    bail!("refused: unknown command operation");
  }
  let dry_run = opt_bool(args, "dry_run", false);
  let path = args.get("path").and_then(Value::as_str);
  let if_fingerprint =
    args.get("if_fingerprint").and_then(Value::as_str);

  let (stack, unlock) =
    fetch_mutable(ctx, stack_key, "command").await?;
  let stamped = unlock::stamped_reason(unlock.as_ref(), Some(reason));
  let guard = ctx.env_locks.lock_for(&stack.id);
  let _held = guard.lock().await;
  let state = ctx.komodo.action_state(&stack.id).await?;
  if state.deploying
    || state.pulling
    || state.destroying
    || state.restarting
  {
    bail!("refused: stack busy; retry after the current operation");
  }
  ctx
    .komodo
    .refresh_cache(&stack.id, stamped.as_deref())
    .await
    .context("RefreshStackCache failed")?;
  let stack = ctx.komodo.get_stack(&stack.id).await?;
  ctx.scrubber.learn_stack(&stack);
  if ctx.scrubber.contains_secret(command)
    || path.is_some_and(|path| ctx.scrubber.contains_secret(path))
  {
    bail!(SECRET_REFUSAL);
  }
  let current = stack_command(&stack, which).clone();
  if op == "replace" {
    let wanted = if_fingerprint
      .context("refused: if_fingerprint is required for replace")?;
    if wanted != fingerprint(&current.command)
      && !(current.command.is_empty() && wanted.is_empty())
    {
      bail!(
        "conflict: if_fingerprint does not match the current command; nothing written"
      );
    }
  }
  if op == "append" && !current.command.is_empty() && path.is_some() {
    bail!(
      "refused: path may only be set when appending to an empty command or replacing"
    );
  }
  let next_text = match op {
    "append" if current.command.is_empty() => command.to_string(),
    "append"
      if command.is_empty()
        || current.command.trim_end() == command
        || current
          .command
          .trim_end()
          .ends_with(&format!("\n{command}")) =>
    {
      current.command.clone()
    }
    "append" => format!("{}\n{command}", current.command.trim_end()),
    "replace" => command.to_string(),
    _ => unreachable!(),
  };
  let next = SystemCommand {
    path: path.unwrap_or(&current.path).to_string(),
    command: canonical_command(&next_text),
    shell_mode: current.shell_mode,
  };
  let changed = next != current;
  let summary = command_result(
    &stack.name,
    which,
    &current,
    &next,
    (op == "append").then_some(command),
    dry_run,
    None,
  );
  if dry_run || !changed {
    return Ok(summary);
  }

  let again = ctx.komodo.get_stack(&stack.id).await?;
  if stack_command(&again, which) != &current {
    bail!(
      "conflict: command changed since it was read; nothing written, re-run"
    );
  }
  let env_before = fingerprint(&stack.config.environment);
  let rest_before = command_rest_fingerprint(&stack, which);
  let partial = match which {
    "pre_deploy" => _PartialStackConfig {
      pre_deploy: Some(next.clone()),
      ..Default::default()
    },
    "post_deploy" => _PartialStackConfig {
      post_deploy: Some(next.clone()),
      ..Default::default()
    },
    _ => unreachable!(),
  };
  let t0 = chrono_now_ms();
  ctx
    .komodo
    .update_stack_partial(&stack.id, partial, stamped.as_deref())
    .await
    .context("UpdateStack failed")?;
  let update = find_env_update(ctx, &stack.id, t0).await?;
  verify_command_write(
    ctx,
    &stack,
    which,
    &current,
    &next,
    &env_before,
    &rest_before,
    &update,
  )
  .await?;
  Ok(command_result(
    &stack.name,
    which,
    &current,
    &next,
    (op == "append").then_some(command),
    false,
    Some(&update.id),
  ))
}

fn stack_command<'a>(
  stack: &'a Stack,
  which: &str,
) -> &'a SystemCommand {
  match which {
    "pre_deploy" => &stack.config.pre_deploy,
    "post_deploy" => &stack.config.post_deploy,
    _ => unreachable!(),
  }
}

fn canonical_command(command: &str) -> String {
  let command = command.trim_end();
  if command.is_empty() {
    String::new()
  } else {
    format!("{command}\n")
  }
}

fn command_rest_fingerprint(stack: &Stack, which: &str) -> String {
  let mut value =
    serde_json::to_value(&stack.config).unwrap_or(json!({}));
  if let Some(config) = value.as_object_mut() {
    config.remove(which);
  }
  fingerprint(&value.to_string())
}

fn command_summary(command: &str) -> Value {
  json!({
    "fingerprint": fingerprint(command),
    "lines": command.lines().count(),
  })
}

fn command_result(
  stack: &str,
  which: &str,
  before: &SystemCommand,
  after: &SystemCommand,
  appended: Option<&str>,
  dry_run: bool,
  update_id: Option<&str>,
) -> Value {
  let changed = before != after;
  let op = if appended.is_some() {
    "append"
  } else {
    "replace"
  };
  let mut out = json!({
    "stack": stack,
    "which": which,
    "op": op,
    "changed": changed,
    "dry_run": dry_run,
    "path": after.path,
    "shell_mode": after.shell_mode,
    "diff": {
      "before": command_summary(&before.command),
      "after": command_summary(&after.command),
      "appended_lines": if changed { appended.map_or(0, |command| command.lines().count()) } else { 0 },
    },
    "note": "check stack_history before deploying",
  });
  if let Some(appended) = appended {
    out["appended"] = json!(appended);
  }
  if let Some(update_id) = update_id {
    out["update_id"] = json!(update_id);
  }
  out
}

#[allow(clippy::too_many_arguments)]
async fn verify_command_write(
  ctx: &Ctx<'_>,
  stack: &Stack,
  which: &str,
  before: &SystemCommand,
  after: &SystemCommand,
  env_before: &str,
  rest_before: &str,
  update: &Update,
) -> anyhow::Result<()> {
  let expected = if before == &SystemCommand::default() {
    None
  } else {
    Some(rendered_command_assignment(which, before)?)
  };
  if !command_matches_prev(
    &update.prev_toml,
    which,
    expected.as_deref(),
  ) {
    bail!(
      "error: concurrent writers; manual check needed (update {})",
      update.id,
    );
  }
  let stored = ctx.komodo.get_stack(&stack.id).await?;
  if stack_command(&stored, which) != after {
    let got = stack_command(&stored, which);
    bail!(
      "verification failed: stored command does not equal the computed command (command {} != {}, path_match={}, shell_mode_match={})",
      fingerprint(&got.command),
      fingerprint(&after.command),
      got.path == after.path,
      got.shell_mode == after.shell_mode,
    );
  }
  if fingerprint(&stored.config.environment) != env_before {
    bail!("verification failed: environment fingerprint changed");
  }
  if command_rest_fingerprint(&stored, which) != rest_before {
    bail!("verification failed: rest-of-config fingerprint changed");
  }
  Ok(())
}

fn rendered_command_assignment(
  which: &str,
  command: &SystemCommand,
) -> anyhow::Result<String> {
  let mut value = serde_json::Map::new();
  value.insert(which.into(), json!(command));
  toml_pretty::to_string(&value, toml_pretty_options())
    .map_err(|_| anyhow!("unreadable prev_toml"))
}

/// Like-for-like check against Core's export. toml_pretty writes command
/// objects as dotted keys (`pre_deploy.path = …`) under `[stack.config]`,
/// and its multiline strings are not valid TOML, so this never parses.
/// Both sides use the same extractor, so an omitted empty `path` or a
/// multiline command's continuation lines cannot cause a false race.
fn command_matches_prev(
  rendered: &str,
  which: &str,
  expected: Option<&str>,
) -> bool {
  let actual = command_block(rendered, which);
  match expected {
    None => actual.is_none(),
    Some(expected) => actual == command_block(expected, which),
  }
}

/// The contiguous `which.*` assignment block. A multiline string opens on
/// its assignment line and closes on a later line, so continuation lines
/// stay in the block until the next dotted key.
fn command_block(rendered: &str, which: &str) -> Option<String> {
  let prefix = format!("{which}.");
  let mut lines = Vec::new();
  let mut seen = false;
  let mut continued = false;
  for line in rendered.lines() {
    let quotes = line.matches("\"\"\"").count();
    if line.starts_with(&prefix) {
      seen = true;
      lines.push(line);
      if quotes % 2 == 1 {
        continued = !continued;
      }
    } else if seen && continued {
      lines.push(line);
      if quotes % 2 == 1 {
        continued = false;
      }
    } else if seen {
      break;
    }
  }
  seen.then(|| lines.join("\n"))
}

fn chrono_now_ms() -> i64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_millis() as i64)
    .unwrap_or(0)
}

/// The Update `UpdateStack` created. The write returns the Stack, so the
/// Update is the newest UpdateStack on this stack at or after `t0` whose
/// asserted-actor log names this session.
async fn find_env_update(
  ctx: &Ctx<'_>,
  stack_id: &str,
  t0: i64,
) -> anyhow::Result<Update> {
  let mut query = stack_updates_query(stack_id);
  query.insert("operation", "UpdateStack");
  query.insert("start_ts", bson::doc! { "$gte": t0 });
  let page = ctx.komodo.list_updates(query, 0).await?;
  let item = page
    .updates
    .into_iter()
    .max_by_key(|u| u.start_ts)
    .context("UpdateStack wrote, but no Update was listed")?;
  let update = ctx.komodo.get_update(&item.id).await?;
  let actor = update
    .logs
    .iter()
    .find(|l| l.stage == ACTOR_LOG_STAGE)
    .map(|l| l.stdout.as_str())
    .unwrap_or("");
  if !actor.contains(ctx.komodo.actor()) {
    bail!("Update {id} is not this session's write", id = update.id);
  }
  Ok(update)
}

enum VerifyFail {
  Lost { update_id: String },
  Mismatch(String),
}

#[allow(clippy::too_many_arguments)]
async fn verify_env_write(
  ctx: &Ctx<'_>,
  stack: &Stack,
  name: &str,
  base: &str,
  new_env: &str,
  others_before: &BTreeMap<String, String>,
  rest_before: &str,
  update: &komodo_client::entities::update::Update,
) -> Result<(), VerifyFail> {
  let stored = ctx
    .komodo
    .get_stack(&stack.id)
    .await
    .map_err(|e| VerifyFail::Mismatch(e.to_string()))?;
  // Lost update first: compare Core's stored environment assignment to the
  // same assignment rendered from the buffer we spliced. Assignment text is
  // required because toml_pretty 2.0.0 does not escape multiline values, so
  // parsing is not a round trip for backslashes. Both assignments being absent
  // is valid when the base env is empty and Core skips the empty string.
  let prev_assign = environment_assignment(&update.prev_toml);
  let base_assign = environment_assignment(&export_env_toml(base));
  if prev_assign != base_assign {
    return Err(VerifyFail::Lost {
      update_id: update.id.clone(),
    });
  }
  let same = |a: &str, b: &str| {
    a.trim_end_matches('\n') == b.trim_end_matches('\n')
  };
  // After-write byte check: stored env equals the splice. Only a trailing
  // newline may differ.
  if !same(&stored.config.environment, new_env) {
    return Err(VerifyFail::Mismatch(
      "stored environment does not equal the splice".into(),
    ));
  }
  let others_after =
    others_fingerprints(&stored.config.environment, name);
  if others_after != *others_before {
    return Err(VerifyFail::Mismatch(
      "another key's fingerprint changed".into(),
    ));
  }
  if rest_fingerprint(&stored) != rest_before {
    return Err(VerifyFail::Mismatch(
      "rest-of-config fingerprint changed".into(),
    ));
  }
  let diff_stage = update
    .logs
    .iter()
    .find(|l| l.stage == DIFF_LOG_STAGE)
    .map(|l| l.stdout.as_str())
    .unwrap_or("");
  let names = diff_names(diff_stage);
  if !names.contains(&name.to_string()) {
    return Err(VerifyFail::Mismatch(format!(
      "config diff does not name {name}"
    )));
  }
  Ok(())
}

/// toml_pretty options copied from Core's `TOML_PRETTY_OPTIONS`. komodo_mcp
/// does not link komodo_core, so the two must stay in step.
fn toml_pretty_options() -> toml_pretty::Options<'static> {
  toml_pretty::Options {
    tab: "  ",
    skip_empty_string: true,
    skip_empty_object: true,
    max_inline_array_length: 30,
    inline_array: false,
  }
}

/// Render an env the way Core's Update export does. toml_pretty 2.0.0 writes
/// a multiline string as a basic multiline string with no escapes.
fn export_env_toml(env: &str) -> String {
  let value = serde_json::json!({ "environment": env });
  toml_pretty::to_string(&value, toml_pretty_options())
    .unwrap_or_default()
}

#[cfg(test)]
pub(crate) fn export_stack_resource_toml(
  name: &str,
  config: &komodo_client::entities::stack::StackConfig,
) -> String {
  let head = serde_json::json!({ "name": name });
  let mut projected = serde_json::Map::new();
  projected.insert("branch".into(), json!(config.branch));
  projected.insert("environment".into(), json!(config.environment));
  if config.pre_deploy != SystemCommand::default() {
    projected.insert(
      "pre_deploy".into(),
      serde_json::to_value(&config.pre_deploy).unwrap_or_default(),
    );
  }
  if config.post_deploy != SystemCommand::default() {
    projected.insert(
      "post_deploy".into(),
      serde_json::to_value(&config.post_deploy).unwrap_or_default(),
    );
  }
  let opts = toml_pretty_options();
  let mut out = String::from("[[stack]]\n");
  out.push_str(
    &toml_pretty::to_string(&head, opts).unwrap_or_default(),
  );
  out.push_str("\n[stack.config]\n");
  out.push_str(
    &toml_pretty::to_string(&projected, opts).unwrap_or_default(),
  );
  out
}

fn diff_names(rendered: &str) -> Vec<String> {
  let mut names = Vec::new();
  for line in rendered.lines() {
    // Env lines are indented two spaces:
    // `  + NAME = …`, `  - NAME (was …)`, `  ~ NAME: … -> …`.
    // A field line (`~ config.branch: …`) is not indented. Do not trim
    // before the indent check: `trim` would drop the two spaces.
    let Some(rest) = line
      .strip_prefix("  + ")
      .or_else(|| line.strip_prefix("  - "))
      .or_else(|| line.strip_prefix("  ~ "))
    else {
      continue;
    };
    let token =
      rest.split([' ', '=', ':']).next().unwrap_or("").trim();
    if token.is_empty() || token.starts_with('(') {
      continue;
    }
    names.push(token.to_string());
  }
  names
}

#[allow(clippy::too_many_arguments)]
fn result_ok(
  stack: &str,
  name: &str,
  op: &str,
  before: &str,
  after: &str,
  update_id: &str,
  race_repaired: bool,
  other: Option<EnvDiff>,
) -> Value {
  json!({
    "stack": stack,
    "name": name,
    "op": op,
    "changed": true,
    "dry_run": false,
    "diff": diff_env(before, after),
    "base_fingerprint": fingerprint(before),
    "update_id": update_id,
    "race_repaired": race_repaired,
    "other_writer": other,
    "note": "check stack_history before deploying",
  })
}
