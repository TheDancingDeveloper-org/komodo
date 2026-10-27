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
  Operation,
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

fn decision_json(policy: &Policy, name: &str) -> Value {
  match policy.decide(name) {
    Decision::Allowed => json!("allowed"),
    Decision::NotAllowlisted => {
      json!("read-only (not in KOMODO_MCP_WRITE_STACKS)")
    }
    Decision::Protected => json!(
      "protected (requires exact name in KOMODO_MCP_ALLOW_PROTECTED)"
    ),
  }
}

/// Resolve the stack (by id or name) and enforce the mutation allowlist on
/// its *resolved name*, so passing an id cannot bypass a name rule.
async fn fetch_mutable(
  ctx: &Ctx<'_>,
  stack: &str,
) -> anyhow::Result<Stack> {
  let s = fetch(ctx, stack).await?;
  match ctx.policy.decide(&s.name) {
    Decision::Allowed => Ok(s),
    Decision::NotAllowlisted => Err(anyhow!(
      "refused: stack `{}` is not in the mutation allowlist. This server is \
       read-only for it; add it to KOMODO_MCP_WRITE_STACKS to allow writes \
       and deploys.",
      s.name
    )),
    Decision::Protected => Err(anyhow!(
      "refused: stack `{}` is protected (matches KOMODO_MCP_PROTECTED_STACKS). \
       Mutating it requires its exact name in KOMODO_MCP_ALLOW_PROTECTED. \
       Remember a prod deploy kills sessions living in the prod pod.",
      s.name
    )),
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
  let items: Vec<Value> = matches
    .iter()
    .map(|s| {
      json!({
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
        "mutations": decision_json(ctx.policy, &s.name),
      })
    })
    .collect();
  Ok(json!({ "count": items.len(), "stacks": items }))
}

async fn get_stack(
  ctx: &Ctx<'_>,
  args: &Value,
) -> anyhow::Result<Value> {
  let s = fetch(ctx, arg_str(args, "stack")?).await?;
  let mut v = project_stack(&s);
  v["mutations"] = decision_json(ctx.policy, &s.name);
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
  let s = fetch_mutable(ctx, name).await?;
  if is_env_path(&s, path) {
    bail!(
      "refused: `{path}` is an env file. Writing it would commit secret \
       values to the stack's repo; set env through Komodo/Infisical instead."
    );
  }
  // Refresh first: diffing against or writing over a stale cache is how
  // earlier deploys clobbered newer commits.
  ctx.komodo.refresh_cache(&s.id, reason).await?;
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
  let update =
    ctx.komodo.write_file(&s.id, path, content, reason).await?;
  ctx.komodo.refresh_cache(&s.id, reason).await?;
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
  let s = fetch_mutable(ctx, name).await?;
  let state = ctx.komodo.action_state(&s.id).await?;
  if state.deploying
    || state.pulling
    || state.destroying
    || state.restarting
  {
    bail!("refused: stack `{}` is busy ({state:?})", s.name);
  }
  let started = ctx.komodo.deploy(&s.id, services, reason).await?;
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
  let stack = fetch_mutable(ctx, stack_key).await?;
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
    .refresh_cache(&stack.id, Some(reason))
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
    .update_stack_partial(&stack.id, new_env.clone(), Some(reason))
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
  // Lost update first: Core's prev_toml env must be the buffer we spliced.
  // Compared as text extracted from the export, never as a raw secret log.
  // Only a trailing newline may differ. A fingerprint match is not enough:
  // a concurrent edit of this key, a comment or an unparsed line must
  // still be reported.
  // Core writes prev_toml with toml_pretty 2.0.0, which emits a multiline
  // string as `"""\n{val}"""` and does not escape backslashes. Extracting
  // that does not return the bytes we sent. Render the spliced base the
  // same way and compare the two extractions, so a `\` in a value is not
  // reported as a race.
  // Compare the assignment text, not extracted bytes. Core writes
  // prev_toml with toml_pretty 2.0.0 as a multiline string and does not
  // escape backslashes, so extraction is not a round trip. Rendering the
  // spliced base with the same options produces the same assignment.
  let prev_assign = environment_assignment(&update.prev_toml);
  let base_assign = environment_assignment(&export_env_toml(base));
  if prev_assign.is_none() || prev_assign != base_assign {
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

/// A resource export in Core's shape: `[[stack]]` then `[stack.config]`,
/// with the env rendered by the same toml_pretty options Core uses.
#[cfg(test)]
pub(crate) fn export_env_resource_toml(
  name: &str,
  env: &str,
) -> String {
  let head = serde_json::json!({ "name": name });
  let config = serde_json::json!({
    "branch": "main",
    "environment": env,
  });
  let opts = toml_pretty_options();
  let mut out = String::from("[[stack]]\n");
  out.push_str(
    &toml_pretty::to_string(&head, opts).unwrap_or_default(),
  );
  out.push_str("\n[stack.config]\n");
  out.push_str(
    &toml_pretty::to_string(&config, opts).unwrap_or_default(),
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
