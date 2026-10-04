//! Server-side redaction. Two layers:
//!
//! 1. **Projection (default-deny).** A stack is serialized with Komodo's own
//!    types and then projected field by field. Every field must be
//!    classified in the tables below; a field that is not (for example one
//!    upstream adds in a later release) is withheld, never passed through.
//!    `tests::every_stack_field_is_classified` fails on a rebase that adds a
//!    field, forcing an explicit decision.
//! 2. **Scrubbing (defence in depth).** Every tool result is walked before it
//!    is returned and any known secret value (every env value of every stack
//!    the call touched, plus common token shapes) is replaced with
//!    `[redacted:NAME]`. This catches values echoed by deploy logs, container
//!    logs, health-check output and API error messages.

use std::sync::{LazyLock, Mutex};

use komodo_client::entities::stack::Stack;
use names_diff::{
  fingerprint, normalize_value, parse_env, reference_of,
};
use regex::Regex;
use serde_json::{Map, Value, json};

/// How a field of the serialized stack is presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
  /// Safe: passed through (still scrubbed).
  Pass,
  /// A `KEY=VALUE` block: names (and references) only.
  Env,
  /// A secret: only whether it is set.
  SetOnly,
  /// Free text that may embed secrets: fingerprint + line count.
  Fingerprint,
  /// A `{path, command}` system command: path shown, command fingerprinted.
  Command,
  /// A list of `{path, contents, ...}` files: contents fingerprinted.
  Files,
  /// A list of `{path, contents}` errors: contents scrubbed and truncated.
  Errors,
  /// Nested projection (config / info).
  Config,
  Info,
}

pub const TOP_FIELDS: &[(&str, Class)] = &[
  ("_id", Class::Pass),
  ("name", Class::Pass),
  ("description", Class::Pass),
  ("template", Class::Pass),
  ("tags", Class::Pass),
  ("base_permission", Class::Pass),
  ("updated_at", Class::Pass),
  ("config", Class::Config),
  ("info", Class::Info),
];

pub const CONFIG_FIELDS: &[(&str, Class)] = &[
  ("swarm_id", Class::Pass),
  ("server_id", Class::Pass),
  ("links", Class::Pass),
  ("project_name", Class::Pass),
  ("auto_pull", Class::Pass),
  ("run_build", Class::Pass),
  ("poll_for_updates", Class::Pass),
  ("auto_update", Class::Pass),
  ("auto_update_all_services", Class::Pass),
  ("auto_update_skip_services", Class::Pass),
  ("destroy_before_deploy", Class::Pass),
  ("skip_secret_interp", Class::Pass),
  ("linked_repo", Class::Pass),
  ("git_provider", Class::Pass),
  ("git_https", Class::Pass),
  ("git_account", Class::Pass),
  ("repo", Class::Pass),
  ("branch", Class::Pass),
  ("commit", Class::Pass),
  ("clone_path", Class::Pass),
  ("reclone", Class::Pass),
  ("webhook_enabled", Class::Pass),
  ("webhook_secret", Class::SetOnly),
  ("webhook_force_deploy", Class::Pass),
  ("files_on_host", Class::Pass),
  ("run_directory", Class::Pass),
  ("file_paths", Class::Pass),
  ("env_file_path", Class::Pass),
  ("additional_env_files", Class::Pass),
  ("config_files", Class::Pass),
  ("send_alerts", Class::Pass),
  ("registry_provider", Class::Pass),
  ("registry_account", Class::Pass),
  ("pre_deploy", Class::Command),
  ("post_deploy", Class::Command),
  ("extra_args", Class::Pass),
  ("build_extra_args", Class::Pass),
  ("compose_cmd_wrapper", Class::Fingerprint),
  ("compose_cmd_wrapper_include", Class::Pass),
  ("ignore_services", Class::Pass),
  ("file_contents", Class::Fingerprint),
  ("environment", Class::Env),
];

pub const INFO_FIELDS: &[(&str, Class)] = &[
  ("missing_files", Class::Pass),
  ("deployed_project_name", Class::Pass),
  ("deployed_hash", Class::Pass),
  ("deployed_message", Class::Pass),
  // `docker compose config` output: has interpolated env values.
  ("deployed_config", Class::Fingerprint),
  ("deployed_contents", Class::Files),
  ("deployed_services", Class::Pass),
  ("latest_services", Class::Pass),
  ("remote_contents", Class::Files),
  ("remote_errors", Class::Errors),
  ("latest_hash", Class::Pass),
  ("latest_message", Class::Pass),
];

const WITHHELD: &str =
  "[withheld: field not classified for redaction]";

fn classify(table: &[(&str, Class)], key: &str) -> Option<Class> {
  table.iter().find(|(k, _)| *k == key).map(|(_, c)| *c)
}

fn text_summary(s: &str) -> Value {
  json!({ "fingerprint": fingerprint(s), "lines": s.lines().count() })
}

/// Names-only view of an env block.
pub fn env_view(env: &str) -> Value {
  let parsed = parse_env(env);
  let entries: Vec<Value> = parsed
    .entries
    .iter()
    .map(|e| {
      let mut m = Map::new();
      m.insert("name".into(), json!(e.name));
      m.insert(
        "fingerprint".into(),
        json!(fingerprint(normalize_value(&e.value))),
      );
      if let Some(r) = reference_of(&e.value) {
        m.insert("reference".into(), json!(r));
      }
      Value::Object(m)
    })
    .collect();
  let mut out = json!({
    "count": entries.len(),
    "variables": entries,
  });
  if parsed.unparsed_lines > 0 {
    out["unparsed_lines"] = json!(parsed.unparsed_lines);
  }
  out
}

fn project_value(class: Class, v: &Value) -> Value {
  match class {
    Class::Pass => v.clone(),
    Class::Env => env_view(v.as_str().unwrap_or_default()),
    Class::SetOnly => json!({
      "set": !(v.is_null() || v.as_str().is_some_and(str::is_empty))
    }),
    Class::Fingerprint => match v {
      Value::Null => Value::Null,
      Value::String(s) if s.is_empty() => json!(""),
      Value::String(s) => text_summary(s),
      other => text_summary(&other.to_string()),
    },
    Class::Command => {
      let path = v.get("path").cloned().unwrap_or(Value::Null);
      let command = v.get("command").and_then(Value::as_str).unwrap_or("");
      json!({
        "path": path,
        "command": if command.is_empty() { json!("") } else { text_summary(command) },
        "shell_mode": v.get("shell_mode").cloned().unwrap_or(Value::Null),
      })
    }
    Class::Files => match v {
      Value::Array(files) => Value::Array(
        files
          .iter()
          .map(|f| {
            let contents =
              f.get("contents").and_then(Value::as_str).unwrap_or("");
            let mut m = Map::new();
            m.insert("path".into(), f.get("path").cloned().unwrap_or(Value::Null));
            m.insert("fingerprint".into(), json!(fingerprint(contents)));
            m.insert("lines".into(), json!(contents.lines().count()));
            for k in ["services", "requires"] {
              if let Some(x) = f.get(k) {
                m.insert(k.into(), x.clone());
              }
            }
            Value::Object(m)
          })
          .collect(),
      ),
      other => other.clone(),
    },
    Class::Errors => match v {
      Value::Array(errs) => Value::Array(
        errs
          .iter()
          .map(|e| {
            json!({
              "path": e.get("path").cloned().unwrap_or(Value::Null),
              "error": truncate(
                &strip_html(e.get("contents").and_then(Value::as_str).unwrap_or("")),
                500,
              ),
            })
          })
          .collect(),
      ),
      other => other.clone(),
    },
    Class::Config => project_object(CONFIG_FIELDS, v),
    Class::Info => project_object(INFO_FIELDS, v),
  }
}

fn project_object(table: &[(&str, Class)], v: &Value) -> Value {
  let Value::Object(obj) = v else {
    return Value::Null;
  };
  let mut out = Map::new();
  for (k, val) in obj {
    let projected = match classify(table, k) {
      Some(class) => project_value(class, val),
      None => json!(WITHHELD),
    };
    out.insert(k.clone(), projected);
  }
  Value::Object(out)
}

/// The redacted view of a stack. Default-deny: unknown fields are withheld.
pub fn project_stack(stack: &Stack) -> Value {
  match serde_json::to_value(stack) {
    Ok(v) => {
      let mut out = project_object(TOP_FIELDS, &v);
      // Mongo ids serialize as {"$oid": ".."}; flatten for readability.
      if let Some(id) =
        out.get("_id").and_then(|i| i.get("$oid")).cloned()
      {
        out["_id"] = id;
      }
      out
    }
    Err(_) => json!({ "error": "stack could not be serialized" }),
  }
}

/// Env names that look like credentials: their values are scrubbed even
/// when short.
fn secretish(name: &str) -> bool {
  let n = name.to_ascii_uppercase();
  [
    "PASS",
    "SECRET",
    "TOKEN",
    "KEY",
    "PRIVATE",
    "CREDENTIAL",
    "AUTH",
    "PAT",
    "DSN",
    "COOKIE",
    "SESSION",
    "SALT",
  ]
  .iter()
  .any(|p| n.contains(p))
}

static TOKEN_SHAPES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
  [
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    r"\bgh[pousr]_[A-Za-z0-9]{20,}",
    r"\bgithub_pat_[A-Za-z0-9_]{20,}",
    r"\bsk-[A-Za-z0-9_\-]{20,}",
    r"\btskey-[A-Za-z0-9\-]{10,}",
    r"\bxox[abpr]-[A-Za-z0-9\-]{10,}",
    r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
  ]
  .iter()
  .map(|r| Regex::new(r).expect("static regex"))
  .collect()
});

/// Replaces known secret values in tool output.
#[derive(Default)]
pub struct Scrubber {
  /// (value, name), longest value first.
  values: Mutex<Vec<(String, String)>>,
  /// Public identifiers (stack names). An env value equal to one of these
  /// is not scrubbed unless its variable name looks like a credential, so
  /// `TAILSCALE_HOSTNAME=vogt-dev` does not turn every mention of the stack
  /// into `[redacted:TAILSCALE_HOSTNAME]`.
  public: Mutex<std::collections::HashSet<String>>,
}

impl Scrubber {
  pub fn learn(&self, name: &str, value: &str) {
    let value = value.trim();
    if value.is_empty() || reference_of(value).is_some() {
      return;
    }
    let long_enough = value.chars().count() >= 8
      || (secretish(name) && value.chars().count() >= 3);
    if !long_enough {
      return;
    }
    let mut values = self.values.lock().unwrap();
    for v in [value, normalize_value(value)] {
      if v.is_empty() {
        continue;
      }
      match values.iter_mut().find(|(x, _)| x == v) {
        // Same value under a credential-like name wins, so the public
        // identifier exemption cannot apply to it.
        Some(existing) => {
          if secretish(name) && !secretish(&existing.1) {
            existing.1 = name.to_string();
          }
        }
        None => values.push((v.to_string(), name.to_string())),
      }
    }
    values.sort_by_key(|v| std::cmp::Reverse(v.0.len()));
  }

  /// Learn every secret-bearing value of a stack.
  pub fn learn_stack(&self, stack: &Stack) {
    self.public.lock().unwrap().insert(stack.name.clone());
    for e in parse_env(&stack.config.environment).entries {
      self.learn(&e.name, &e.value);
    }
    self.learn("webhook_secret", &stack.config.webhook_secret);
  }

  pub fn scrub_str(&self, s: &str) -> String {
    let mut out = s.to_string();
    let public = self.public.lock().unwrap();
    for (value, name) in self.values.lock().unwrap().iter() {
      if public.contains(value) && !secretish(name) {
        continue;
      }
      if out.contains(value.as_str()) {
        out =
          out.replace(value.as_str(), &format!("[redacted:{name}]"));
      }
    }
    for re in TOKEN_SHAPES.iter() {
      if re.is_match(&out) {
        out = re.replace_all(&out, "[redacted:token]").into_owned();
      }
    }
    out
  }

  pub fn scrub(&self, v: &mut Value) {
    match v {
      Value::String(s) => *s = self.scrub_str(s),
      Value::Array(a) => a.iter_mut().for_each(|x| self.scrub(x)),
      Value::Object(o) => o.values_mut().for_each(|x| self.scrub(x)),
      _ => {}
    }
  }
}

static TAG: LazyLock<Regex> = LazyLock::new(|| {
  Regex::new(r"</?[a-zA-Z][^<>]*>").expect("static regex")
});

/// Remove the HTML spans Komodo puts in update logs and decode entities.
pub fn strip_html(s: &str) -> String {
  TAG
    .replace_all(s, "")
    .replace("&lt;", "<")
    .replace("&gt;", ">")
    .replace("&quot;", "\"")
    .replace("&#39;", "'")
    .replace("&amp;", "&")
}

/// The last `n` lines of `s`.
pub fn tail(s: &str, n: usize) -> String {
  let lines: Vec<&str> = s.lines().collect();
  let start = lines.len().saturating_sub(n);
  lines[start..].join("\n")
}

pub fn truncate(s: &str, max: usize) -> String {
  if s.chars().count() <= max {
    s.to_string()
  } else {
    let cut: String = s.chars().take(max).collect();
    format!("{cut}… [truncated]")
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use komodo_client::entities::{
    FileContents, SystemCommand,
    stack::{StackConfig, StackInfo, StackRemoteFileContents},
  };

  pub const SECRET_A: &str = "s3cr3t-A-value-FAKE-0001";
  pub const SECRET_B: &str = "ghp_FAKEFAKEFAKEFAKEFAKEFAKE0123";
  pub const SECRET_C: &str = "webhook-FAKE-secret-0003";

  fn stack() -> Stack {
    Stack {
      name: "vogt-dev".into(),
      config: StackConfig {
        environment: format!(
          "PLAIN=1\nDB_PASSWORD={SECRET_A}\nGH_TOKEN=\"{SECRET_B}\"\nREF=[[infisical://apps/prod/HOMELAB_X]]"
        ),
        webhook_secret: SECRET_C.into(),
        pre_deploy: SystemCommand {
          path: "personal/vogt-dev".into(),
          command: format!("echo {SECRET_A}"),
          ..Default::default()
        },
        file_contents: format!(
          "services:\n  x:\n    environment: [T={SECRET_B}]"
        ),
        ..Default::default()
      },
      info: StackInfo {
        deployed_config: Some(format!("DB_PASSWORD: {SECRET_A}")),
        remote_contents: Some(vec![StackRemoteFileContents {
          path: "vogt.compose.yml".into(),
          contents: format!("# {SECRET_A}\n"),
          ..Default::default()
        }]),
        deployed_contents: Some(vec![FileContents {
          path: "vogt.compose.yml".into(),
          contents: format!("# {SECRET_B}\n"),
        }]),
        remote_errors: Some(vec![FileContents {
          path: "bad.yml".into(),
          contents: format!("<span>failed {SECRET_A}</span>"),
        }]),
        ..Default::default()
      },
      ..Default::default()
    }
  }

  pub fn assert_clean(s: &str) {
    for secret in [SECRET_A, SECRET_B, SECRET_C] {
      assert!(!s.contains(secret), "secret leaked: {s}");
    }
  }

  #[test]
  fn projection_never_emits_values() {
    let s = stack();
    let mut v = project_stack(&s);
    // Projection alone (before scrubbing) must already be clean, except
    // for remote_errors which is scrubbed text.
    let mut no_errors = v.clone();
    no_errors["info"]["remote_errors"] = Value::Null;
    assert_clean(&no_errors.to_string());
    let scrubber = Scrubber::default();
    scrubber.learn_stack(&s);
    scrubber.scrub(&mut v);
    let text = v.to_string();
    assert_clean(&text);
    let names: Vec<&str> = v["config"]["environment"]["variables"]
      .as_array()
      .unwrap()
      .iter()
      .map(|e| e["name"].as_str().unwrap())
      .collect();
    assert_eq!(names, ["PLAIN", "DB_PASSWORD", "GH_TOKEN", "REF"]);
    assert_eq!(
      v["config"]["environment"]["variables"][3]["reference"],
      "[[infisical://apps/prod/HOMELAB_X]]"
    );
    assert_eq!(v["config"]["webhook_secret"]["set"], true);
    assert_eq!(
      v["config"]["pre_deploy"]["path"],
      "personal/vogt-dev"
    );
    assert_eq!(v["name"], "vogt-dev");
    assert!(!text.contains("<span>"));
  }

  #[test]
  fn unknown_fields_are_withheld() {
    let mut raw = serde_json::to_value(stack()).unwrap();
    raw["config"]["new_upstream_field"] = json!(SECRET_A);
    raw["info"]["another_new_field"] = json!(SECRET_B);
    raw["surprise"] = json!(SECRET_C);
    // remote_errors is scrubbed text (layer 2), not projected away.
    raw["info"]["remote_errors"] = Value::Null;
    let v = project_object(TOP_FIELDS, &raw);
    assert_clean(&v.to_string());
    assert_eq!(v["config"]["new_upstream_field"], WITHHELD);
    assert_eq!(v["info"]["another_new_field"], WITHHELD);
    assert_eq!(v["surprise"], WITHHELD);
  }

  /// Fails when a Komodo rebase adds a Stack field: classify it above.
  #[test]
  fn every_stack_field_is_classified() {
    let v = serde_json::to_value(stack()).unwrap();
    for (table, obj) in [
      (TOP_FIELDS, &v),
      (CONFIG_FIELDS, &v["config"]),
      (INFO_FIELDS, &v["info"]),
    ] {
      for key in obj.as_object().unwrap().keys() {
        assert!(
          classify(table, key).is_some(),
          "Stack field `{key}` is not classified in redact.rs"
        );
      }
    }
    // And the reverse: no stale entries for fields that no longer exist.
    let cfg = serde_json::to_value(StackConfig::default()).unwrap();
    for (k, _) in CONFIG_FIELDS {
      assert!(
        cfg.get(*k).is_some(),
        "stale CONFIG_FIELDS entry `{k}`"
      );
    }
  }

  #[test]
  fn scrubber_catches_echoed_values_and_token_shapes() {
    let s = Scrubber::default();
    s.learn("DB_PASSWORD", SECRET_A);
    s.learn("PORT", "8080"); // short and not secret-ish: kept
    s.learn("API_KEY", "abc"); // short but secret-ish: scrubbed
    let out = s.scrub_str(&format!(
      "pw={SECRET_A} port=8080 key=abc gh={SECRET_B} \
       -----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"
    ));
    assert_clean(&out);
    assert!(out.contains("[redacted:DB_PASSWORD]"));
    assert!(out.contains("port=8080"));
    assert!(out.contains("key=[redacted:API_KEY]"));
    assert!(!out.contains("AAAA"));
  }

  #[test]
  fn stack_names_are_public_unless_secret_named() {
    let s = Scrubber::default();
    let mut a = stack();
    a.config.environment =
      "TAILSCALE_HOSTNAME=vogt-prod\nDB_PASSWORD=vogt-prod".into();
    s.learn_stack(&a);
    let mut b = stack();
    b.name = "vogt-prod".into();
    b.config.environment.clear();
    s.learn_stack(&b);
    // Both names learned the value; the secret-named one still scrubs.
    assert_eq!(s.scrub_str("vogt-prod"), "[redacted:DB_PASSWORD]");
    let s = Scrubber::default();
    a.config.environment = "TAILSCALE_HOSTNAME=vogt-prod".into();
    s.learn_stack(&a);
    s.learn_stack(&b);
    assert_eq!(s.scrub_str("stack vogt-prod"), "stack vogt-prod");
  }

  #[test]
  fn references_are_not_scrubbed() {
    let s = Scrubber::default();
    s.learn("X", "[[infisical://apps/prod/HOMELAB_X]]");
    assert_eq!(
      s.scrub_str("[[infisical://apps/prod/HOMELAB_X]]"),
      "[[infisical://apps/prod/HOMELAB_X]]"
    );
  }

  #[test]
  fn html_is_stripped() {
    assert_eq!(
      strip_html(
        "<span class=\"text-red\">error</span>: a &lt;b&gt; &amp; c"
      ),
      "error: a <b> & c"
    );
  }
}
