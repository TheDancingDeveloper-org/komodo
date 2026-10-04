//! The MCP tools. Every tool returns a JSON value that the dispatcher scrubs
//! with the per-call [`Scrubber`] before it leaves the process.

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, anyhow, bail};
use komodo_client::entities::{
  Operation,
  stack::Stack,
  update::{Log, Update, UpdateStatus},
};
use names_diff::{
  EnvChange, EnvDiff, NamedValue, ValueRef, diff_env, diff_file,
  diff_resource_toml, environment_from_toml, fingerprint,
  normalize_value, parse_env,
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
