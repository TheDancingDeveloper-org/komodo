//! Fork-only (TheDancingDeveloper) additions to Core: attribution and
//! names-only change records for config/env/file updates (Vogt WI-865).
//!
//! Two things are recorded on Update records, each as an extra log so the
//! Update schema, the UI and the API types stay untouched:
//!
//! * **`Actor (asserted)`** — the `X-Komodo-Actor` / `X-Komodo-Reason`
//!   request headers. Every agent shares one Komodo API key, so `operator`
//!   alone cannot say *which* session made a change. The headers are
//!   asserted by the API key holder, not authenticated; they attribute, they
//!   do not authorize. Sent by `komodo-mcp` on every mutating call.
//! * **`Config diff (names only)`** / **`File change (names only)`** — what
//!   changed, with env values and non-allowlisted fields shown only as
//!   fingerprints (see `lib/names_diff`). Reading "what changed on this
//!   stack's env" no longer requires dumping `prev_toml`, which holds every
//!   secret in plain text.
//!
//! Hook points (all purely additive, one or two lines each):
//! `api/write/mod.rs` and `api/execute/mod.rs` (header scope),
//! `helpers/update.rs` (stamp), `resource/mod.rs::update` (config diff),
//! `api/write/stack.rs::WriteStackFileContents` (file change).

use std::future::Future;

use axum::{extract::Request, middleware::Next, response::Response};
use komodo_client::entities::{
  stack::Stack,
  update::{Log, Update},
};

pub const ACTOR_HEADER: &str = "x-komodo-actor";
pub const REASON_HEADER: &str = "x-komodo-reason";
pub const ACTOR_LOG_STAGE: &str = "Actor (asserted)";
pub const DIFF_LOG_STAGE: &str = "Config diff (names only)";
pub const FILE_LOG_STAGE: &str = "File change (names only)";

/// The asserted actor of the request being handled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Asserted {
  pub actor: Option<String>,
  pub reason: Option<String>,
}

tokio::task_local! {
  static ASSERTED: Asserted;
}

fn clean(value: &str) -> Option<String> {
  let v: String = value
    .chars()
    .filter(|c| c.is_ascii_graphic() || *c == ' ')
    .take(200)
    .collect();
  let v = v.trim();
  (!v.is_empty()).then(|| v.to_string())
}

impl Asserted {
  pub fn from_headers(headers: &axum::http::HeaderMap) -> Asserted {
    let get = |name: &str| {
      headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(clean)
    };
    Asserted {
      actor: get(ACTOR_HEADER),
      reason: get(REASON_HEADER),
    }
  }

  fn log(&self) -> Option<Log> {
    if self.actor.is_none() && self.reason.is_none() {
      return None;
    }
    let mut body = String::new();
    if let Some(a) = &self.actor {
      body.push_str(&format!("actor: {a}\n"));
    }
    if let Some(r) = &self.reason {
      body.push_str(&format!("reason: {r}\n"));
    }
    body.push_str(
      "source: X-Komodo-Actor/X-Komodo-Reason headers (asserted by the API key holder, not verified)",
    );
    Some(Log::simple(ACTOR_LOG_STAGE, body))
  }
}

/// Router middleware: make the request's asserted actor visible to the
/// handler (and to `make_update`/`add_update` beneath it).
pub async fn scope_layer(req: Request, next: Next) -> Response {
  let asserted = Asserted::from_headers(req.headers());
  ASSERTED.scope(asserted, next.run(req)).await
}

/// Carry the current asserted actor into a future that will be spawned.
pub fn propagate<F: Future>(
  fut: F,
) -> impl Future<Output = F::Output> {
  let asserted = ASSERTED.try_with(Clone::clone).unwrap_or_default();
  ASSERTED.scope(asserted, fut)
}

/// Add the actor log to an update, once. No-op outside a request scope
/// (background tasks) or when the caller sent no headers.
pub fn stamp(update: &mut Update) {
  if update.logs.iter().any(|l| l.stage == ACTOR_LOG_STAGE) {
    return;
  }
  if let Ok(Some(log)) = ASSERTED.try_with(Asserted::log) {
    update.logs.push(log);
  }
}

/// Record a names-only diff of `prev_toml` -> `current_toml`.
pub fn push_config_diff(update: &mut Update) {
  if update.prev_toml.is_empty() && update.current_toml.is_empty() {
    return;
  }
  let body = match names_diff::diff_resource_toml(
    &update.prev_toml,
    &update.current_toml,
  ) {
    Ok(diff) => diff.render(),
    Err(e) => format!("names-only diff unavailable: {e}"),
  };
  update.push_simple_log(DIFF_LOG_STAGE, body);
}

/// Record a content-free summary of a stack file write, relative to
/// Komodo's cached copy of that file.
pub fn push_file_change(
  update: &mut Update,
  stack: &Stack,
  path: &str,
  contents: &str,
) {
  let norm = |p: &str| p.trim_start_matches("./").to_string();
  let before = stack
    .info
    .remote_contents
    .iter()
    .flatten()
    .find(|f| norm(&f.path) == norm(path))
    .map(|f| f.contents.as_str());
  let c = names_diff::diff_file(before, contents);
  let mut body = format!(
    "path: {path}\nbefore: {} (Komodo's cached copy)\nafter: {}\nlines: +{} -{}\n",
    c.before.as_deref().unwrap_or("(not in cache: new file)"),
    c.after,
    c.lines_added,
    c.lines_removed,
  );
  // An env file written through Komodo: also name the keys that changed.
  let file = path.rsplit('/').next().unwrap_or(path);
  if file.ends_with(".env") || file.starts_with(".env") {
    let d =
      names_diff::diff_env(before.unwrap_or_default(), contents);
    let mut cd = names_diff::ConfigDiff::default();
    cd.env.insert(path.to_string(), d);
    body.push_str(&cd.render());
  }
  update.push_simple_log(FILE_LOG_STAGE, body);
}

#[cfg(test)]
mod tests {
  use axum::http::{HeaderMap, HeaderValue};
  use komodo_client::entities::stack::StackRemoteFileContents;

  use super::*;

  const SECRET: &str = "FAKE-secret-value-0000001";

  #[test]
  fn headers_are_sanitised() {
    let mut h = HeaderMap::new();
    h.insert(
      ACTOR_HEADER,
      HeaderValue::from_static("vogt-session:abc"),
    );
    h.insert(
      REASON_HEADER,
      HeaderValue::from_static("  bump\tdigest "),
    );
    let a = Asserted::from_headers(&h);
    assert_eq!(a.actor.as_deref(), Some("vogt-session:abc"));
    assert_eq!(a.reason.as_deref(), Some("bumpdigest"));
    assert_eq!(
      Asserted::from_headers(&HeaderMap::new()),
      Asserted::default()
    );
  }

  #[tokio::test]
  async fn stamp_only_inside_scope_and_once() {
    let mut u = Update::default();
    stamp(&mut u);
    assert!(u.logs.is_empty(), "no scope, no stamp");
    let a = Asserted {
      actor: Some("vogt-session:abc".into()),
      reason: Some("why".into()),
    };
    let u = ASSERTED
      .scope(a, async {
        let mut u = Update::default();
        stamp(&mut u);
        stamp(&mut u);
        u
      })
      .await;
    assert_eq!(u.logs.len(), 1);
    assert!(u.logs[0].stdout.contains("actor: vogt-session:abc"));
    assert!(u.logs[0].stdout.contains("reason: why"));
  }

  #[tokio::test]
  async fn propagate_crosses_spawn() {
    let a = Asserted {
      actor: Some("x".into()),
      reason: None,
    };
    let u = ASSERTED
      .scope(a, async {
        tokio::spawn(propagate(async {
          let mut u = Update::default();
          stamp(&mut u);
          u
        }))
        .await
        .unwrap()
      })
      .await;
    assert_eq!(u.logs.len(), 1);
    // Without propagate a spawned task has no actor.
    let u = tokio::spawn(async {
      let mut u = Update::default();
      stamp(&mut u);
      u
    })
    .await
    .unwrap();
    assert!(u.logs.is_empty());
  }

  #[test]
  fn config_diff_log_has_no_values() {
    let mut u = Update {
      prev_toml: format!(
        "[[stack]]\nname = \"s\"\n[stack.config]\nenvironment = \"\"\"\nA=1\nTOKEN={SECRET}\n\"\"\"\n"
      ),
      current_toml: "[[stack]]\nname = \"s\"\n[stack.config]\nenvironment = \"\"\"\nA=1\nTOKEN=rotated-FAKE-0000002\nNEW=[[infisical://apps/prod/NEW]]\n\"\"\"\n".into(),
      ..Default::default()
    };
    push_config_diff(&mut u);
    let log = &u.logs[0];
    assert_eq!(log.stage, DIFF_LOG_STAGE);
    assert!(log.stdout.contains("~ TOKEN"));
    assert!(
      log.stdout.contains("+ NEW = [[infisical://apps/prod/NEW]]")
    );
    assert!(!log.stdout.contains(SECRET));
    assert!(!log.stdout.contains("rotated-FAKE"));
  }

  #[test]
  fn file_change_log_has_no_content() {
    let stack = Stack {
      info: komodo_client::entities::stack::StackInfo {
        remote_contents: Some(vec![StackRemoteFileContents {
          path: "compose.yml".into(),
          contents: format!("a\n# {SECRET}\n"),
          ..Default::default()
        }]),
        ..Default::default()
      },
      ..Default::default()
    };
    let mut u = Update::default();
    push_file_change(&mut u, &stack, "./compose.yml", "a\nb\n");
    let body = &u.logs[0].stdout;
    assert!(body.contains("lines: +1 -1"), "{body}");
    assert!(!body.contains(SECRET));
    let mut u = Update::default();
    push_file_change(
      &mut u,
      &stack,
      ".env",
      &format!("K={SECRET}\n"),
    );
    let body = &u.logs[0].stdout;
    assert!(body.contains("+ K = sha256:"), "{body}");
    assert!(!body.contains(SECRET));
  }
}
