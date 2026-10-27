use std::{collections::BTreeSet, time::Duration};

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use komodo_client::entities::{update::Update, user::User};
use serde::Deserialize;

use crate::{komodo::Komodo, tools::ACTOR_LOG_STAGE};

pub const SCOPES: &[&str] = &["env", "command", "files", "deploy"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
  stack: String,
  until: String,
  scope: BTreeSet<String>,
  #[serde(default)]
  note: String,
}

#[derive(Debug, Clone)]
pub struct Unlock {
  pub id: String,
  pub until: DateTime<Utc>,
  pub scope: BTreeSet<String>,
  pub by: String,
}

/// `KOMODO_MCP_UNLOCK__` + upper(stack), non-alphanumerics mapped to `_`
/// (Core allows only `[A-Za-z0-9_]` in names). The mapping is lossy, so
/// the entry's `stack` field must match the stack exactly.
pub fn variable_name(stack: &str) -> String {
  let upper: String = stack
    .chars()
    .map(|c| {
      if c.is_ascii_alphanumeric() {
        c.to_ascii_uppercase()
      } else {
        '_'
      }
    })
    .collect();
  format!("KOMODO_MCP_UNLOCK__{upper}")
}

pub fn stamped_reason(
  unlock: Option<&Unlock>,
  reason: Option<&str>,
) -> Option<String> {
  let reason = reason.unwrap_or_default();
  let stamped = match unlock {
    Some(u) => format!(
      "[unlock={} until={}] {reason}",
      u.id,
      u.until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    ),
    // Only a resolved unlock may lead with the tag stack_history reads.
    None if reason.trim_start().starts_with("[unlock=") => {
      format!("(unverified) {reason}")
    }
    None => reason.to_string(),
  };
  (!stamped.is_empty()).then_some(stamped)
}

fn actor_asserted(update: &Update) -> bool {
  update.logs.iter().any(|l| l.stage == ACTOR_LOG_STAGE)
}

/// Query for Variable updates. The newest 20 are filtered to this stack's
/// unlock variable by reading each update's logs.
pub fn variable_updates_query() -> bson::Document {
  bson::doc! {
    "operation": {
      "$in": ["CreateVariable", "UpdateVariableValue", "DeleteVariable"]
    }
  }
}

pub fn unlock_id_from_actor(update: &Update) -> Option<String> {
  let log =
    update.logs.iter().find(|l| l.stage == ACTOR_LOG_STAGE)?;
  for line in log.stdout.lines() {
    let Some((_, value)) = line.split_once(": ") else {
      continue;
    };
    if line.trim_start().starts_with("reason") {
      let value = value.trim();
      let rest = value.strip_prefix("[unlock=")?;
      let (id, _) = rest.split_once(" until=")?;
      if !id.is_empty() {
        return Some(id.to_string());
      }
    }
  }
  None
}

/// Core's log layout for the Variable writes in
/// `bin/core/src/api/write/variable.rs`. `CreateVariable` and
/// `DeleteVariable` log `{variable:#?}`; `UpdateVariableValue` logs this
/// span markup with the raw old and new values.
const CREATE_STAGE: &str = "Create Variable";
const UPDATE_STAGE: &str = "Update Variable Value";
const DELETE_STAGE: &str = "Delete Variable";
const SPAN_VARIABLE: &str =
  "<span class=\"text-muted-foreground\">variable</span>: ";
const SPAN_FROM: &str = "<span class=\"text-muted-foreground\">from</span>: <span class=\"text-red-500\">";
const SPAN_TO: &str = "</span>\n<span class=\"text-muted-foreground\">to</span>:   <span class=\"text-green-500\">";

/// Scan at most this many Variable updates when building history.
const HISTORY_SCAN: usize = 200;
const HISTORY_LIMIT: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableOp {
  Create,
  UpdateValue,
  Delete,
}

impl VariableOp {
  fn history_name(self) -> &'static str {
    match self {
      VariableOp::Create => "unlock-set",
      VariableOp::UpdateValue => "unlock-changed",
      VariableOp::Delete => "unlock-removed",
    }
  }
}

/// Undo Rust's `{:?}` escaping of a `String`. `None` if it is not one.
fn unescape_debug(quoted: &str) -> Option<String> {
  let inner = quoted.strip_prefix('"')?.strip_suffix('"')?;
  let mut out = String::with_capacity(inner.len());
  let mut chars = inner.chars();
  while let Some(c) = chars.next() {
    if c != '\\' {
      out.push(c);
      continue;
    }
    match chars.next()? {
      'n' => out.push('\n'),
      'r' => out.push('\r'),
      't' => out.push('\t'),
      '0' => out.push('\0'),
      '\\' => out.push('\\'),
      '"' => out.push('"'),
      '\'' => out.push('\''),
      'u' => {
        if chars.next()? != '{' {
          return None;
        }
        let hex: String =
          chars.by_ref().take_while(|c| *c != '}').collect();
        out
          .push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
      }
      _ => return None,
    }
  }
  Some(out)
}

/// One field of a `{:#?}`-printed `Variable` (four-space indent).
fn debug_field(stdout: &str, field: &str) -> Option<String> {
  let prefix = format!("    {field}: ");
  stdout
    .lines()
    .find_map(|l| l.strip_prefix(&prefix))
    .and_then(|v| v.strip_suffix(','))
    .and_then(unescape_debug)
}

/// Parse a Variable Update in Core's own log format. `Some((op, value))`
/// only when the update is about exactly `name`; `value` is the value the
/// update logged (the new value, or the deleted one).
pub fn parse_variable_update(
  update: &Update,
  name: &str,
) -> Option<(VariableOp, String)> {
  use komodo_client::entities::Operation;
  let (op, stage) = match update.operation {
    Operation::CreateVariable => (VariableOp::Create, CREATE_STAGE),
    Operation::UpdateVariableValue => {
      (VariableOp::UpdateValue, UPDATE_STAGE)
    }
    Operation::DeleteVariable => (VariableOp::Delete, DELETE_STAGE),
    _ => return None,
  };
  let log = update.logs.iter().find(|l| l.stage == stage)?;
  let value = match op {
    VariableOp::Create | VariableOp::Delete => {
      if debug_field(&log.stdout, "name")? != name {
        return None;
      }
      debug_field(&log.stdout, "value")?
    }
    VariableOp::UpdateValue => {
      let rest = log
        .stdout
        .strip_prefix(&format!(
          "{SPAN_VARIABLE}'{name}'\n{SPAN_FROM}"
        ))?
        .strip_suffix("</span>")?;
      // The new value is last; a value containing the marker yields a
      // suffix of it, which then fails the exact match (fails closed).
      rest.rsplit_once(SPAN_TO)?.1.to_string()
    }
  };
  Some((op, value))
}

/// The newest Variable update (Create, UpdateValue or Delete) for `name`.
async fn newest_variable_update(
  komodo: &Komodo,
  name: &str,
) -> anyhow::Result<Option<(VariableOp, String, Update)>> {
  let q = variable_updates_query();
  let mut page = 0;
  loop {
    let res = komodo.list_updates(q.clone(), page).await?;
    for item in res.updates {
      let update = komodo.get_update(&item.id).await?;
      if let Some((op, value)) = parse_variable_update(&update, name)
      {
        return Ok(Some((op, value, update)));
      }
    }
    match res.next_page {
      Some(next) => page = next,
      None => return Ok(None),
    }
  }
}

/// The newest 20 Variable updates for this stack's unlock variable, each
/// described from its own log.
pub async fn history(
  komodo: &Komodo,
  stack: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
  use serde_json::{Value, json};
  let name = variable_name(stack);
  let q = variable_updates_query();
  let mut page = 0u32;
  let mut scanned = 0usize;
  let mut out = Vec::new();
  loop {
    let res = komodo.list_updates(q.clone(), page).await?;
    for item in res.updates {
      if scanned >= HISTORY_SCAN || out.len() >= HISTORY_LIMIT {
        return Ok(out);
      }
      scanned += 1;
      let update = komodo.get_update(&item.id).await?;
      let Some((op, value)) = parse_variable_update(&update, &name)
      else {
        continue;
      };
      let mut entry = json!({
        "operation": op.history_name(),
        "by": item.username,
        "update_id": update.id,
        "until": Value::Null,
        "scope": Value::Null,
      });
      if op != VariableOp::Delete
        && let Ok(parsed) = serde_json::from_str::<Entry>(&value)
      {
        entry["until"] = json!(parsed.until);
        entry["scope"] =
          json!(parsed.scope.into_iter().collect::<Vec<_>>());
      }
      out.push(entry);
    }
    match res.next_page {
      Some(next) => page = next,
      None => return Ok(out),
    }
  }
}

pub async fn resolve(
  komodo: &Komodo,
  api_user: Option<&User>,
  stack: &str,
  scope: &str,
  max_ttl: Duration,
) -> anyhow::Result<Unlock> {
  resolve_inner(komodo, api_user, stack, Some(scope), max_ttl).await
}

pub async fn resolve_status(
  komodo: &Komodo,
  api_user: Option<&User>,
  stack: &str,
  max_ttl: Duration,
) -> anyhow::Result<Unlock> {
  resolve_inner(komodo, api_user, stack, None, max_ttl).await
}

async fn resolve_inner(
  komodo: &Komodo,
  api_user: Option<&User>,
  stack: &str,
  scope: Option<&str>,
  max_ttl: Duration,
) -> anyhow::Result<Unlock> {
  let name = variable_name(stack);
  let variable = komodo.get_variable(&name).await.with_context(|| format!("refused: stack `{stack}` is protected; a person must set Komodo Variable {name}"))?;
  if variable.is_secret {
    bail!("refused: unlock variable must be non-secret");
  }
  let entry: Entry = serde_json::from_str(&variable.value)
    .context("refused: malformed unlock JSON")?;
  let until = DateTime::parse_from_rfc3339(&entry.until)
    .context("refused: unlock until must be RFC3339")?
    .with_timezone(&Utc);
  let _ = &entry.note;
  if entry.stack != stack {
    bail!("refused: unlock stack does not exactly match `{stack}`");
  }
  if entry.scope.is_empty() {
    bail!("refused: unlock scope must be non-empty");
  }
  if let Some(bad) =
    entry.scope.iter().find(|s| !SCOPES.contains(&s.as_str()))
  {
    bail!("refused: unknown unlock scope `{bad}`");
  }
  if let Some(scope) = scope
    && !entry.scope.contains(scope)
  {
    bail!("refused: unlock does not include `{scope}` scope");
  }
  let now = Utc::now();
  if now >= until {
    bail!("refused: unlock expired at {}", until.to_rfc3339());
  }
  let max_ms = i64::try_from(max_ttl.as_millis()).unwrap_or(i64::MAX);
  if until.timestamp_millis() - now.timestamp_millis() > max_ms {
    bail!("refused: unlock until exceeds KOMODO_MCP_UNLOCK_MAX_TTL");
  }
  let Some(api_user) = api_user else {
    bail!(
      "refused: unlocks unavailable: this MCP could not read its own Komodo user at startup (GetUser; upgrade Core first)"
    );
  };
  let (op, logged, grant) = newest_variable_update(komodo, &name)
    .await?
    .context("refused: no audit update found for unlock variable")?;
  if op == VariableOp::Delete {
    bail!(
      "refused: unlock not honoured: its newest audit update {} is a DeleteVariable",
      grant.id
    );
  }
  if logged != variable.value {
    bail!(
      "refused: unlock not honoured: the variable's value does not match its newest audit update {}",
      grant.id
    );
  }
  if grant.start_ts + max_ms < until.timestamp_millis() {
    bail!(
      "refused: unlock lifetime exceeds KOMODO_MCP_UNLOCK_MAX_TTL"
    );
  }
  if grant.operator == api_user.id {
    bail!(
      "refused: unlock not honoured: it was set by this MCP's own API user"
    );
  }
  let setter = komodo.get_username(&grant.operator).await?;
  match setter.service_user {
    Some(false) if !User::is_service_user(&grant.operator) => {}
    Some(_) => bail!(
      "refused: unlock not honoured: it was set by a service user"
    ),
    None => bail!(
      "refused: unlock not honoured: Core did not report whether the setter is a service user (upgrade Core)"
    ),
  }
  if actor_asserted(&grant) {
    bail!(
      "refused: unlock not honoured: setter update has an Actor (asserted) stage"
    );
  }
  let by = setter.username;
  Ok(Unlock {
    id: grant.id,
    until,
    scope: entry.scope,
    by,
  })
}

#[cfg(test)]
mod tests {
  use komodo_client::entities::{
    Operation, update::Log, variable::Variable,
  };

  use super::*;

  fn update(
    operation: Operation,
    stage: &str,
    stdout: String,
  ) -> Update {
    Update {
      operation,
      logs: vec![Log::simple(stage, stdout)],
      ..Default::default()
    }
  }

  #[test]
  fn parses_core_debug_log_with_escapes_and_exact_name() {
    let value = "{\"note\":\"tab\\t é \\\\ \\u{7}\"}\u{7}";
    let variable = Variable {
      name: "KOMODO_MCP_UNLOCK__A".into(),
      value: value.into(),
      ..Default::default()
    };
    let u = update(
      Operation::CreateVariable,
      CREATE_STAGE,
      format!("{variable:#?}"),
    );
    assert_eq!(
      parse_variable_update(&u, "KOMODO_MCP_UNLOCK__A"),
      Some((VariableOp::Create, value.to_string()))
    );
    assert_eq!(
      parse_variable_update(&u, "KOMODO_MCP_UNLOCK__AB"),
      None
    );
  }

  #[test]
  fn update_value_with_marker_in_value_fails_closed() {
    let new = format!("x{SPAN_TO}y");
    let stdout = format!(
      "{SPAN_VARIABLE}'N'\n{SPAN_FROM}old</span>\n<span class=\"text-muted-foreground\">to</span>:   <span class=\"text-green-500\">{new}</span>"
    );
    let u =
      update(Operation::UpdateVariableValue, UPDATE_STAGE, stdout);
    let (_, logged) = parse_variable_update(&u, "N").unwrap();
    assert_ne!(logged, new);
    assert_eq!(parse_variable_update(&u, "M"), None);
  }

  #[test]
  fn variable_name_matches_core_rule() {
    assert_eq!(
      variable_name("vogt-prod"),
      "KOMODO_MCP_UNLOCK__VOGT_PROD"
    );
  }

  #[test]
  fn client_source_never_writes_variables() {
    let source = include_str!("komodo.rs");
    for forbidden in
      ["CreateVariable", "UpdateVariableValue", "DeleteVariable"]
    {
      assert!(!source.contains(forbidden));
    }
  }
}
