//! A minimal MCP server over stdio: newline-delimited JSON-RPC 2.0, with
//! `initialize`, `ping`, `tools/list` and `tools/call`. Requests are handled
//! concurrently (a long `deploy_stack` does not block `ping`); responses are
//! written by a single writer task.

use std::{sync::Arc, time::Duration};

use serde_json::{Value, json};
use tokio::{
  io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
  sync::mpsc,
};

use crate::{
  config::Policy,
  komodo::Komodo,
  redact::Scrubber,
  tools::{self, Ctx},
};

pub const SUPPORTED_PROTOCOLS: &[&str] =
  &["2025-06-18", "2025-03-26", "2024-11-05"];

pub struct Server {
  pub komodo: Komodo,
  pub policy: Policy,
  pub poll: Duration,
}

impl Server {
  /// Run one tool call with its own scrubber and return the MCP result.
  /// Every string in the result (including error text) is scrubbed.
  pub async fn call_tool(&self, name: &str, args: &Value) -> Value {
    let scrubber = Scrubber::default();
    let ctx = Ctx {
      komodo: &self.komodo,
      policy: &self.policy,
      scrubber: &scrubber,
      poll: self.poll,
    };
    let (mut body, is_error) =
      match tools::call(&ctx, name, args).await {
        Ok(v) => (v, false),
        Err(e) => (json!({ "error": format!("{e:#}") }), true),
      };
    scrubber.scrub(&mut body);
    let text = serde_json::to_string_pretty(&body)
      .unwrap_or_else(|_| String::from("{}"));
    json!({
      "content": [{ "type": "text", "text": text }],
      "isError": is_error,
    })
  }

  pub async fn handle(&self, msg: Value) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method =
      msg.get("method").and_then(Value::as_str).unwrap_or("");
    // Notifications (no id) get no response.
    let id = id?;
    let result = match method {
      "initialize" => {
        let requested = msg
          .pointer("/params/protocolVersion")
          .and_then(Value::as_str)
          .unwrap_or(SUPPORTED_PROTOCOLS[0]);
        let version = if SUPPORTED_PROTOCOLS.contains(&requested) {
          requested
        } else {
          SUPPORTED_PROTOCOLS[0]
        };
        Ok(json!({
          "protocolVersion": version,
          "capabilities": { "tools": { "listChanged": false } },
          "serverInfo": {
            "name": "komodo-mcp",
            "version": env!("CARGO_PKG_VERSION"),
          },
          "instructions": instructions(&self.policy),
        }))
      }
      "ping" => Ok(json!({})),
      "tools/list" => Ok(json!({ "tools": tools::list() })),
      "tools/call" => {
        let name = msg
          .pointer("/params/name")
          .and_then(Value::as_str)
          .unwrap_or("");
        let args = msg
          .pointer("/params/arguments")
          .cloned()
          .unwrap_or_else(|| json!({}));
        Ok(self.call_tool(name, &args).await)
      }
      "resources/list" => Ok(json!({ "resources": [] })),
      "prompts/list" => Ok(json!({ "prompts": [] })),
      other => Err((-32601, format!("method not found: {other}"))),
    };
    Some(match result {
      Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
      Err((code, message)) => json!({
        "jsonrpc": "2.0", "id": id,
        "error": { "code": code, "message": message },
      }),
    })
  }
}

pub fn instructions(policy: &Policy) -> String {
  let mode = if policy.read_only() {
    String::from(
      "This server is READ-ONLY: write_stack_file and deploy_stack will refuse every stack.",
    )
  } else {
    format!(
      "Mutations allowed for stacks matching {:?}; protected patterns {:?} need an exact opt-in (opted in: {:?}).",
      policy.write, policy.protected, policy.allow_protected
    )
  };
  format!(
    "Komodo stacks via typed tools; use these instead of curl against the Komodo API. \
     Secrets are redacted server-side: env is names + fingerprints only. {mode} \
     Typical deploy: stack_lookup -> read_stack_file -> write_stack_file -> deploy_stack -> container_health. \
     To answer 'what changed and who': stack_history(since_last_successful_deploy=true) or env_diff(against={{last_successful_deploy:true}})."
  )
}

/// Serve MCP on stdin/stdout until stdin closes.
pub async fn serve_stdio(server: Server) -> anyhow::Result<()> {
  let server = Arc::new(server);
  let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
  let writer = tokio::spawn(async move {
    let mut out = tokio::io::stdout();
    while let Some(msg) = rx.recv().await {
      let mut line = serde_json::to_string(&msg).unwrap_or_default();
      line.push('\n');
      if out.write_all(line.as_bytes()).await.is_err() {
        break;
      }
      let _ = out.flush().await;
    }
  });
  let mut lines = BufReader::new(tokio::io::stdin()).lines();
  let mut tasks = tokio::task::JoinSet::new();
  while let Some(line) = lines.next_line().await? {
    if line.trim().is_empty() {
      continue;
    }
    let msg: Value = match serde_json::from_str(&line) {
      Ok(v) => v,
      Err(_) => {
        let _ = tx.send(json!({
          "jsonrpc": "2.0", "id": null,
          "error": { "code": -32700, "message": "parse error" },
        }));
        continue;
      }
    };
    let server = server.clone();
    let tx = tx.clone();
    tasks.spawn(async move {
      if let Some(resp) = server.handle(msg).await {
        let _ = tx.send(resp);
      }
    });
  }
  while tasks.join_next().await.is_some() {}
  drop(tx);
  let _ = writer.await;
  Ok(())
}
