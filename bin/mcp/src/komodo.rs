//! Thin wrapper over the fork's typed client (`komodo_client`). All request
//! bodies are built from Komodo's own request types, so the body shape
//! (`params.stack` vs `params.id`, method names) is checked by the compiler
//! rather than by trial and error.

use std::time::Duration;

use komodo_client::{
  KomodoClient,
  api::{
    execute::DeployStack,
    read::{
      GetStack, GetStackActionState, GetStackLog, GetUpdate,
      InspectStackContainer, ListStackServices, ListStacks,
      ListUpdates, ListUpdatesResponse,
    },
    write::{RefreshStackCache, WriteStackFileContents},
  },
  entities::{
    docker::container::Container,
    stack::{Stack, StackActionState, StackListItem, StackService},
    update::{Log, Update, UpdateStatus},
  },
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::config::{Config, sanitize_header};

/// Header carrying the asserted actor of a mutating call. Komodo Core in
/// this fork stamps it on the resulting Update (see `bin/core/src/tdd`).
pub const ACTOR_HEADER: &str = "x-komodo-actor";
pub const REASON_HEADER: &str = "x-komodo-reason";

#[derive(Clone)]
pub struct Komodo {
  client: KomodoClient,
  actor: String,
}

fn http(headers: HeaderMap) -> reqwest::Client {
  reqwest::Client::builder()
    .default_headers(headers)
    .connect_timeout(Duration::from_secs(10))
    .timeout(Duration::from_secs(120))
    .build()
    .unwrap_or_default()
}

impl Komodo {
  pub fn new(config: &Config) -> Komodo {
    let client =
      KomodoClient::new(&config.url, &config.key, &config.secret)
        .set_reqwest(http(HeaderMap::new()));
    Komodo {
      client,
      actor: config.actor.clone(),
    }
  }

  /// A client whose requests carry the actor stamp and optional reason.
  fn stamped(&self, reason: Option<&str>) -> KomodoClient {
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&self.actor) {
      headers.insert(HeaderName::from_static(ACTOR_HEADER), v);
    }
    if let Some(r) =
      reason.map(sanitize_header).filter(|r| !r.is_empty())
      && let Ok(v) = HeaderValue::from_str(&r)
    {
      headers.insert(HeaderName::from_static(REASON_HEADER), v);
    }
    self.client.clone().set_reqwest(http(headers))
  }

  pub async fn version(&self) -> anyhow::Result<String> {
    self.client.core_version().await
  }

  pub async fn list_stacks(
    &self,
  ) -> anyhow::Result<Vec<StackListItem>> {
    self.client.read(ListStacks::default()).await
  }

  /// The full stack, including secret-bearing fields. Callers must pass it
  /// through `redact::project_stack` and register it with the scrubber.
  pub async fn get_stack(
    &self,
    stack: &str,
  ) -> anyhow::Result<Stack> {
    self
      .client
      .read(GetStack {
        stack: stack.to_string(),
      })
      .await
  }

  pub async fn action_state(
    &self,
    stack: &str,
  ) -> anyhow::Result<StackActionState> {
    self
      .client
      .read(GetStackActionState {
        stack: stack.to_string(),
      })
      .await
  }

  pub async fn refresh_cache(
    &self,
    stack: &str,
    reason: Option<&str>,
  ) -> anyhow::Result<()> {
    self
      .stamped(reason)
      .write(RefreshStackCache {
        stack: stack.to_string(),
      })
      .await
      .map(|_| ())
  }

  pub async fn write_file(
    &self,
    stack: &str,
    file_path: &str,
    contents: &str,
    reason: Option<&str>,
  ) -> anyhow::Result<Update> {
    self
      .stamped(reason)
      .write(WriteStackFileContents {
        stack: stack.to_string(),
        file_path: file_path.to_string(),
        contents: contents.to_string(),
      })
      .await
  }

  pub async fn deploy(
    &self,
    stack: &str,
    services: Vec<String>,
    reason: Option<&str>,
  ) -> anyhow::Result<Update> {
    self
      .stamped(reason)
      .execute(DeployStack {
        stack: stack.to_string(),
        services,
        stop_time: None,
      })
      .await
  }

  pub async fn get_update(&self, id: &str) -> anyhow::Result<Update> {
    self.client.read(GetUpdate { id: id.to_string() }).await
  }

  /// Poll an update until it completes, or give up after `timeout`.
  pub async fn wait_update(
    &self,
    id: &str,
    timeout: Duration,
    interval: Duration,
  ) -> anyhow::Result<(Update, bool)> {
    let start = tokio::time::Instant::now();
    loop {
      let update = self.get_update(id).await?;
      if update.status == UpdateStatus::Complete {
        return Ok((update, true));
      }
      if start.elapsed() >= timeout {
        return Ok((update, false));
      }
      tokio::time::sleep(interval).await;
    }
  }

  pub async fn list_updates(
    &self,
    query: bson::Document,
    page: u32,
  ) -> anyhow::Result<ListUpdatesResponse> {
    self
      .client
      .read(ListUpdates {
        query: Some(query),
        page,
      })
      .await
  }

  pub async fn services(
    &self,
    stack: &str,
  ) -> anyhow::Result<Vec<StackService>> {
    self
      .client
      .read(ListStackServices {
        stack: stack.to_string(),
      })
      .await
  }

  pub async fn inspect(
    &self,
    stack: &str,
    service: &str,
  ) -> anyhow::Result<Container> {
    self
      .client
      .read(InspectStackContainer {
        stack: stack.to_string(),
        service: service.to_string(),
      })
      .await
  }

  pub async fn logs(
    &self,
    stack: &str,
    service: &str,
    tail: u64,
    timestamps: bool,
  ) -> anyhow::Result<Log> {
    self
      .client
      .read(GetStackLog {
        stack: stack.to_string(),
        services: vec![service.to_string()],
        tail,
        timestamps,
      })
      .await
  }
}

/// Mongo filter for the updates of one stack.
pub fn stack_updates_query(stack_id: &str) -> bson::Document {
  bson::doc! { "target.type": "Stack", "target.id": stack_id }
}

#[cfg(test)]
mod tests {
  use komodo_client::api::write::UpdateStack;
  use mogh_resolver::HasResponse;
  use serde::Serialize;
  use serde_json::{Value, json};

  use super::*;

  /// The exact envelope `KomodoClient` posts to `/read|/write|/execute`.
  fn envelope<T: Serialize + HasResponse>(req: T) -> Value {
    json!({ "type": T::req_type(), "params": req })
  }

  #[test]
  fn body_shapes_match_komodo_types() {
    assert_eq!(
      envelope(GetStack {
        stack: "vogt-dev".into()
      }),
      json!({"type": "GetStack", "params": {"stack": "vogt-dev"}})
    );
    assert_eq!(
      envelope(RefreshStackCache { stack: "s".into() }),
      json!({"type": "RefreshStackCache", "params": {"stack": "s"}})
    );
    assert_eq!(
      envelope(WriteStackFileContents {
        stack: "s".into(),
        file_path: "vogt.compose.yml".into(),
        contents: "x".into(),
      }),
      json!({"type": "WriteStackFileContents", "params": {
        "stack": "s", "file_path": "vogt.compose.yml", "contents": "x"
      }})
    );
    assert_eq!(
      envelope(DeployStack {
        stack: "s".into(),
        services: vec![],
        stop_time: None,
      }),
      json!({"type": "DeployStack", "params": {
        "stack": "s", "services": [], "stop_time": null
      }})
    );
    assert_eq!(
      envelope(GetUpdate { id: "u".into() }),
      json!({"type": "GetUpdate", "params": {"id": "u"}})
    );
    // The trap from the incident log: UpdateStack takes `id`, not `stack`.
    // This server never sends UpdateStack, but pin the shape so a future
    // tool cannot get it wrong.
    let v = envelope(UpdateStack {
      id: "s".into(),
      config: Default::default(),
    });
    assert!(v["params"].get("id").is_some());
    assert!(v["params"].get("stack").is_none());
    // GetStack also accepts `id`/`name` aliases on the server side.
    let parsed: GetStack =
      serde_json::from_value(json!({"name": "vogt-dev"})).unwrap();
    assert_eq!(parsed.stack, "vogt-dev");
  }

  #[test]
  fn update_query_shape() {
    let q = stack_updates_query("abc");
    assert_eq!(q.get_str("target.type").unwrap(), "Stack");
    assert_eq!(q.get_str("target.id").unwrap(), "abc");
  }
}
