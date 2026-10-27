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

pub fn variable_name(stack: &str) -> String {
  format!("KOMODO_MCP_UNLOCK__{}", stack.to_ascii_uppercase())
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

fn history_op(
  operation: &komodo_client::entities::Operation,
) -> Option<&'static str> {
  use komodo_client::entities::Operation;
  match operation {
    Operation::CreateVariable => Some("unlock-set"),
    Operation::UpdateVariableValue => Some("unlock-changed"),
    Operation::DeleteVariable => Some("unlock-removed"),
    _ => None,
  }
}

/// Newest 20 Variable updates that mention this stack's unlock variable.
pub async fn history(
  komodo: &Komodo,
  stack: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
  use serde_json::{Value, json};
  let name = variable_name(stack);
  let needle = format!("'{name}'");
  let q = variable_updates_query();
  let mut page = 0u32;
  let mut seen = 0usize;
  let mut out = Vec::new();
  loop {
    let res = komodo.list_updates(q.clone(), page).await?;
    for item in res.updates {
      if seen >= 20 {
        return Ok(out);
      }
      seen += 1;
      let Some(operation) = history_op(&item.operation) else {
        continue;
      };
      let update = komodo.get_update(&item.id).await?;
      if !update.logs.iter().any(|l| l.stdout.contains(&needle)) {
        continue;
      }
      let mut entry = json!({
        "operation": operation,
        "by": item.username,
        "update_id": update.id,
      });
      if let Ok(variable) = komodo.get_variable(&name).await
        && let Ok(parsed) =
          serde_json::from_str::<Entry>(&variable.value)
      {
        entry["until"] = json!(parsed.until);
        entry["scope"] =
          json!(parsed.scope.into_iter().collect::<Vec<_>>());
      }
      if update.operation
        == komodo_client::entities::Operation::DeleteVariable
      {
        entry["until"] = Value::Null;
        entry["scope"] = Value::Null;
      }
      out.push(entry);
    }
    match res.next_page {
      Some(next) if seen < 20 => page = next,
      _ => return Ok(out),
    }
  }
}

pub async fn resolve(
  komodo: &Komodo,
  api_user: &User,
  stack: &str,
  scope: &str,
  max_ttl: Duration,
) -> anyhow::Result<Unlock> {
  resolve_inner(komodo, api_user, stack, Some(scope), max_ttl).await
}

pub async fn resolve_status(
  komodo: &Komodo,
  api_user: &User,
  stack: &str,
  max_ttl: Duration,
) -> anyhow::Result<Unlock> {
  resolve_inner(komodo, api_user, stack, None, max_ttl).await
}

async fn resolve_inner(
  komodo: &Komodo,
  api_user: &User,
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
  let q = bson::doc! { "operation": { "$in": ["CreateVariable", "UpdateVariableValue"] } };
  let mut page = 0;
  let grant = 'outer: loop {
    let res = komodo.list_updates(q.clone(), page).await?;
    for item in res.updates {
      let update = komodo.get_update(&item.id).await?;
      if update
        .logs
        .iter()
        .any(|l| l.stdout.contains(&format!("'{name}'")))
      {
        break 'outer update;
      }
    }
    page = res.next_page.context(
      "refused: no audit update found for unlock variable",
    )?;
  };
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
  if User::is_service_user(&grant.operator) || setter.service_user {
    bail!(
      "refused: unlock not honoured: it was set by a service user"
    );
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
