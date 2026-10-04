//! End-to-end tests against a mock Komodo Core. The mock speaks the same
//! envelope as Core (`POST /read|/write|/execute`, `{"type", "params"}`),
//! deserializes every request into Komodo's own request types, and serves
//! fixtures stuffed with fake secrets. Each test drives the real tool code
//! through `Server::call_tool` and asserts on what would reach the agent.

use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
  time::Duration,
};

use axum::{
  Json, Router,
  extract::{Path, State},
  http::{HeaderMap, StatusCode},
  routing::post,
};
use komodo_client::{
  api::{
    execute::DeployStack,
    read::{GetStack, GetStackLog, GetUpdate, ListUpdates},
    write::{RefreshStackCache, WriteStackFileContents},
  },
  entities::{
    Operation, ResourceTarget, ResourceTargetVariant, Version,
    docker::{
      ContainerConfig,
      container::{
        Container, ContainerHealth, ContainerListItem,
        ContainerState, ContainerStateStatusEnum, HealthStatusEnum,
        HealthcheckResult,
      },
    },
    stack::{
      Stack, StackActionState, StackConfig, StackInfo, StackListItem,
      StackListItemInfo, StackRemoteFileContents, StackService,
      StackState,
    },
    update::{Log, Update, UpdateListItem, UpdateStatus},
  },
};
use serde_json::{Value, json};

use crate::{
  config::{Policy, split_list},
  komodo::Komodo,
  server::Server,
};

const SECRET_DB: &str = "db-pass-FAKE-0000000001";
const SECRET_GH: &str = "ghp_FAKEFAKEFAKEFAKEFAKEFAKE9999";
const SECRET_OLD: &str = "old-rotated-FAKE-0000000002";
const SECRET_HOOK: &str = "hook-FAKE-0000000003";
const SECRET_LOCAL: &str = "local-only-FAKE-0000000004";
const DEV_ID: &str = "aaaaaaaaaaaaaaaaaaaa0001";
const PROD_ID: &str = "aaaaaaaaaaaaaaaaaaaa0002";
const U_CONFIG: &str = "bbbbbbbbbbbbbbbbbbbb0001";
const U_DEPLOY_OK: &str = "bbbbbbbbbbbbbbbbbbbb0002";
const U_CONFIG_2: &str = "bbbbbbbbbbbbbbbbbbbb0003";
const U_WRITE: &str = "bbbbbbbbbbbbbbbbbbbb0004";
const U_WRITE_NEW: &str = "bbbbbbbbbbbbbbbbbbbb0005";
const U_DEPLOY_NEW: &str = "bbbbbbbbbbbbbbbbbbbb0006";
const ALL_SECRETS: &[&str] =
  &[SECRET_DB, SECRET_GH, SECRET_OLD, SECRET_HOOK, SECRET_LOCAL];

fn assert_clean(v: &Value) {
  let text = v.to_string();
  for s in ALL_SECRETS {
    assert!(!text.contains(s), "secret {s} leaked in: {text}");
  }
}

fn text_of(result: &Value) -> Value {
  let t = result["content"][0]["text"].as_str().unwrap();
  serde_json::from_str(t).unwrap()
}

#[derive(Default)]
struct Mock {
  stacks: Vec<Stack>,
  updates: HashMap<String, Update>,
  update_list: Vec<UpdateListItem>,
  /// (endpoint, type, params, x-komodo-actor)
  requests: Vec<(String, String, Value, Option<String>)>,
  pending_write: Option<(String, String, String)>,
  deploy_fails: bool,
  get_update_calls: usize,
}

type Shared = Arc<Mutex<Mock>>;

fn stack_fixture(id: &str, name: &str, env: &str) -> Stack {
  Stack {
    id: id.into(),
    name: name.into(),
    config: StackConfig {
      environment: env.into(),
      webhook_secret: SECRET_HOOK.into(),
      repo: "indexarr/ops".into(),
      run_directory: format!("personal/{name}/"),
      file_paths: vec!["vogt.compose.yml".into()],
      ..Default::default()
    },
    info: StackInfo {
      deployed_config: Some(format!("DB_PASSWORD: {SECRET_DB}")),
      remote_contents: Some(vec![StackRemoteFileContents {
        path: "vogt.compose.yml".into(),
        contents: format!(
          "services:\n  vogt:\n    image: x@sha256:old\n    # {SECRET_DB}\n"
        ),
        ..Default::default()
      }]),
      latest_hash: Some("abc123".into()),
      ..Default::default()
    },
    ..Default::default()
  }
}

fn list_item(s: &Stack) -> StackListItem {
  StackListItem {
    id: s.id.clone(),
    resource_type: ResourceTargetVariant::Stack,
    name: s.name.clone(),
    template: false,
    tags: vec![],
    info: StackListItemInfo {
      swarm_id: String::new(),
      server_id: "srv".into(),
      files_on_host: false,
      file_contents: false,
      linked_repo: String::new(),
      git_provider: "repo.indexarr.net".into(),
      repo: s.config.repo.clone(),
      branch: "main".into(),
      repo_link: String::new(),
      state: StackState::Running,
      status: None,
      services: vec![],
      project_missing: false,
      missing_files: vec![],
      deployed_hash: Some("abc123".into()),
      latest_hash: Some("abc123".into()),
    },
  }
}

fn update_item(u: &Update) -> UpdateListItem {
  UpdateListItem {
    id: u.id.clone(),
    operation: u.operation,
    start_ts: u.start_ts,
    success: u.success,
    username: "Sprooty".into(),
    operator: u.operator.clone(),
    target: u.target.clone(),
    status: u.status,
    version: Version::default(),
    other_data: String::new(),
  }
}

fn log(
  stage: &str,
  stdout: &str,
  stderr: &str,
  success: bool,
) -> Log {
  Log {
    stage: stage.into(),
    command: String::new(),
    stdout: stdout.into(),
    stderr: stderr.into(),
    success,
    start_ts: 0,
    end_ts: 0,
  }
}

fn new_mock() -> Shared {
  let dev_env = format!(
    "PLAIN=1\nDB_PASSWORD={SECRET_DB}\nGH_TOKEN=\"{SECRET_GH}\"\nREF=[[infisical://apps/prod/HOMELAB_REF]]\nNEW_AFTER_DEPLOY=yes"
  );
  let prod_env = format!("PLAIN=2\nDB_PASSWORD={SECRET_OLD}");
  let dev = stack_fixture(DEV_ID, "vogt-dev", &dev_env);
  let prod = stack_fixture(PROD_ID, "vogt-prod", &prod_env);
  let toml_with = |env: &str| {
    format!(
      "[[stack]]\nname = \"vogt-dev\"\n\n[stack.config]\nbranch = \"main\"\nenvironment = \"\"\"\n{env}\n\"\"\"\n"
    )
  };
  let config_update = Update {
    id: U_CONFIG.into(),
    operation: Operation::UpdateStack,
    start_ts: 1_000,
    success: true,
    status: UpdateStatus::Complete,
    operator: "user-1".into(),
    target: ResourceTarget::Stack(DEV_ID.into()),
    prev_toml: toml_with(&format!(
      "PLAIN=1\nDB_PASSWORD={SECRET_OLD}"
    )),
    current_toml: toml_with(&format!(
      "PLAIN=1\nDB_PASSWORD={SECRET_DB}\nGH_TOKEN={SECRET_GH}\nREF=[[infisical://apps/prod/HOMELAB_REF]]"
    )),
    logs: vec![log(
      "Actor (asserted)",
      "actor: vogt-session:abc\nreason: rotate db password",
      "",
      true,
    )],
    ..Default::default()
  };
  let good_deploy = Update {
    id: U_DEPLOY_OK.into(),
    operation: Operation::DeployStack,
    start_ts: 2_000,
    end_ts: Some(3_000),
    success: true,
    status: UpdateStatus::Complete,
    operator: "user-1".into(),
    target: ResourceTarget::Stack(DEV_ID.into()),
    logs: vec![log("Compose Up", "ok", "", true)],
    ..Default::default()
  };
  let later_config = Update {
    id: U_CONFIG_2.into(),
    operation: Operation::UpdateStack,
    start_ts: 4_000,
    success: true,
    status: UpdateStatus::Complete,
    operator: "user-2".into(),
    target: ResourceTarget::Stack(DEV_ID.into()),
    prev_toml: config_update.current_toml.clone(),
    current_toml: toml_with(&dev_env),
    ..Default::default()
  };
  let write = Update {
    id: U_WRITE.into(),
    operation: Operation::WriteStackContents,
    start_ts: 5_000,
    success: true,
    status: UpdateStatus::Complete,
    operator: "user-2".into(),
    target: ResourceTarget::Stack(DEV_ID.into()),
    logs: vec![
      log(
        "File contents to write",
        &format!("# {SECRET_DB}\n"),
        "",
        true,
      ),
      log("Commit", "1 file changed", "", true),
    ],
    ..Default::default()
  };
  let mut updates = HashMap::new();
  // Newest first, like Core.
  let mut update_list = Vec::new();
  for u in [&write, &later_config, &good_deploy, &config_update] {
    update_list.push(update_item(u));
    updates.insert(u.id.clone(), u.clone());
  }
  Arc::new(Mutex::new(Mock {
    stacks: vec![dev, prod],
    updates,
    update_list,
    ..Default::default()
  }))
}

fn err(msg: &str) -> (StatusCode, Json<Value>) {
  (
    StatusCode::BAD_REQUEST,
    Json(json!({ "error": msg, "trace": [] })),
  )
}

fn find(m: &Mock, key: &str) -> Option<Stack> {
  m.stacks
    .iter()
    .find(|s| s.id == key || s.name == key)
    .cloned()
}

fn matches_query(u: &UpdateListItem, q: &bson::Document) -> bool {
  let target_id = match &u.target {
    ResourceTarget::Stack(id) => id.as_str(),
    _ => "",
  };
  if let Ok(id) = q.get_str("target.id")
    && id != target_id
  {
    return false;
  }
  let op = serde_json::to_value(u.operation).unwrap();
  let op = op.as_str().unwrap();
  match q.get("operation") {
    Some(bson::Bson::String(s)) if s != op => return false,
    Some(bson::Bson::Document(d)) => {
      if let Ok(list) = d.get_array("$in")
        && !list.iter().any(|b| b.as_str() == Some(op))
      {
        return false;
      }
    }
    _ => {}
  }
  if let Ok(success) = q.get_bool("success")
    && success != u.success
  {
    return false;
  }
  if let Ok(d) = q.get_document("start_ts")
    // JSON round-trips small numbers as Int32, as it does for Core.
    && let Some(lt) = d
      .get("$lt")
      .and_then(|b| b.as_i64().or(b.as_i32().map(i64::from)))
    && u.start_ts >= lt
  {
    return false;
  }
  true
}

async fn handle(
  State(state): State<Shared>,
  Path(endpoint): Path<String>,
  headers: HeaderMap,
  Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let ty = body["type"].as_str().unwrap_or_default().to_string();
  let params = body["params"].clone();
  let actor = headers
    .get("x-komodo-actor")
    .and_then(|v| v.to_str().ok())
    .map(String::from);
  let mut m = state.lock().unwrap();
  m.requests.push((
    endpoint.clone(),
    ty.clone(),
    params.clone(),
    actor,
  ));
  // Every request must deserialize into Komodo's own request type: this is
  // the body-shape check.
  macro_rules! parse {
    ($t:ty) => {
      serde_json::from_value::<$t>(params.clone()).map_err(|e| {
        err(&format!("bad {} body: {e}", stringify!($t)))
      })?
    };
  }
  let out = match (endpoint.as_str(), ty.as_str()) {
    ("read", "GetVersion") => json!({ "version": "2.2.0" }),
    ("read", "ListStacks") => {
      json!(m.stacks.iter().map(list_item).collect::<Vec<_>>())
    }
    ("read", "GetStack") => {
      let p = parse!(GetStack);
      json!(find(&m, &p.stack).ok_or_else(|| err("no stack"))?)
    }
    ("read", "GetStackActionState") => {
      json!(StackActionState::default())
    }
    ("read", "GetUpdate") => {
      let p = parse!(GetUpdate);
      if p.id == U_DEPLOY_NEW {
        m.get_update_calls += 1;
        let done = m.get_update_calls >= 2;
        let fails = m.deploy_fails;
        let mut logs = vec![log("Compose Pull", "pulled", "", true)];
        if done && fails {
          logs.push(log(
            "Compose Up",
            "",
            &format!(
              "line 1\n<span class=\"text-red-500\">Error</span>: env DB_PASSWORD={SECRET_DB} rejected &amp; failed"
            ),
            false,
          ));
        }
        json!(Update {
          id: p.id,
          operation: Operation::DeployStack,
          start_ts: 10_000,
          end_ts: done.then_some(70_000),
          status: if done {
            UpdateStatus::Complete
          } else {
            UpdateStatus::InProgress
          },
          success: !(done && fails),
          logs,
          ..Default::default()
        })
      } else {
        json!(m.updates.get(&p.id).ok_or_else(|| err("no update"))?)
      }
    }
    ("read", "ListUpdates") => {
      let p = parse!(ListUpdates);
      let q = p.query.unwrap_or_default();
      let list: Vec<_> = m
        .update_list
        .iter()
        .filter(|u| matches_query(u, &q))
        .cloned()
        .collect();
      json!({ "updates": list, "next_page": null })
    }
    ("read", "ListStackServices") => json!(vec![StackService {
      service: "vogt".into(),
      image: "x@sha256:new".into(),
      container: Some(ContainerListItem {
        name: "vogt-dev-vogt-1".into(),
        image: Some("x@sha256:new".into()),
        state: ContainerStateStatusEnum::Running,
        status: Some("Up 2 minutes (healthy)".into()),
        labels: [("secret.label".to_string(), SECRET_GH.to_string())]
          .into(),
        ..Default::default()
      }),
      ..Default::default()
    }]),
    ("read", "InspectStackContainer") => json!(Container {
      state: Some(ContainerState {
        status: ContainerStateStatusEnum::Running,
        health: Some(ContainerHealth {
          status: HealthStatusEnum::Healthy,
          failing_streak: Some(0),
          log: vec![HealthcheckResult {
            output: Some(format!("ok token={SECRET_GH}")),
            ..Default::default()
          }],
        }),
        ..Default::default()
      }),
      config: Some(ContainerConfig {
        env: vec![format!("DB_PASSWORD={SECRET_DB}")],
        ..Default::default()
      }),
      ..Default::default()
    }),
    ("read", "GetStackLog") => {
      let p = parse!(GetStackLog);
      assert_eq!(p.services, ["vogt"]);
      json!(log(
        "logs",
        &format!(
          "<span>boot</span>\nconnecting with {SECRET_DB}\nready"
        ),
        "",
        true
      ))
    }
    ("write", "RefreshStackCache") => {
      let p = parse!(RefreshStackCache);
      if let Some((sid, path, contents)) = m.pending_write.take() {
        assert_eq!(sid, p.stack);
        let s = m.stacks.iter_mut().find(|s| s.id == sid).unwrap();
        let files = s.info.remote_contents.get_or_insert_default();
        match files.iter_mut().find(|f| f.path == path) {
          Some(f) => f.contents = contents,
          None => files.push(StackRemoteFileContents {
            path,
            contents,
            ..Default::default()
          }),
        }
      }
      json!({})
    }
    ("write", "WriteStackFileContents") => {
      let p = parse!(WriteStackFileContents);
      m.pending_write = Some((
        p.stack.clone(),
        p.file_path.clone(),
        p.contents.clone(),
      ));
      json!(Update {
        id: U_WRITE_NEW.into(),
        operation: Operation::WriteStackContents,
        status: UpdateStatus::Complete,
        success: true,
        logs: vec![
          log("File contents to write", &p.contents, "", true),
          log("Commit", "[main 1234abc] [Komodo] write", "", true),
        ],
        ..Default::default()
      })
    }
    ("execute", "DeployStack") => {
      let _ = parse!(DeployStack);
      m.get_update_calls = 0;
      json!(Update {
        id: U_DEPLOY_NEW.into(),
        operation: Operation::DeployStack,
        status: UpdateStatus::InProgress,
        success: true,
        ..Default::default()
      })
    }
    _ => return Err(err(&format!("unhandled {endpoint} {ty}"))),
  };
  Ok(Json(out))
}

async fn start(policy: Policy) -> (Server, Shared) {
  let state = new_mock();
  let app = Router::new()
    .route("/{endpoint}", post(handle))
    .with_state(state.clone());
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  tokio::spawn(
    async move { axum::serve(listener, app).await.unwrap() },
  );
  let config = crate::config::Config {
    url: format!("http://{addr}"),
    key: "k".into(),
    secret: "s".into(),
    policy: policy.clone(),
    actor: "vogt-session:test".into(),
  };
  let server = Server {
    komodo: Komodo::new(&config),
    policy,
    poll: Duration::from_millis(10),
  };
  (server, state)
}

fn policy(write: &str, allow_protected: &str) -> Policy {
  Policy {
    write: split_list(write),
    protected: split_list("*prod*"),
    allow_protected: split_list(allow_protected),
  }
}

fn types(state: &Shared) -> Vec<String> {
  state
    .lock()
    .unwrap()
    .requests
    .iter()
    .map(|r| r.1.clone())
    .collect()
}

#[tokio::test]
async fn get_stack_redacts_server_side() {
  let (server, _) = start(policy("", "")).await;
  let res = server
    .call_tool("get_stack", &json!({"stack": "vogt-dev"}))
    .await;
  assert_eq!(res["isError"], false);
  let v = text_of(&res);
  assert_clean(&v);
  let names: Vec<_> = v["config"]["environment"]["variables"]
    .as_array()
    .unwrap()
    .iter()
    .map(|e| e["name"].as_str().unwrap().to_string())
    .collect();
  assert_eq!(
    names,
    [
      "PLAIN",
      "DB_PASSWORD",
      "GH_TOKEN",
      "REF",
      "NEW_AFTER_DEPLOY"
    ]
  );
  assert_eq!(v["config"]["webhook_secret"], json!({"set": true}));
  assert_eq!(v["config"]["branch"], "main");
  assert!(v["mutations"].as_str().unwrap().starts_with("read-only"));
}

#[tokio::test]
async fn stack_lookup_by_name_and_id() {
  let (server, _) = start(policy("vogt-dev", "")).await;
  let v = text_of(
    &server
      .call_tool("stack_lookup", &json!({"query": PROD_ID}))
      .await,
  );
  assert_eq!(v["count"], 1);
  assert_eq!(v["stacks"][0]["name"], "vogt-prod");
  assert!(
    v["stacks"][0]["mutations"]
      .as_str()
      .unwrap()
      .starts_with("protected")
  );
  let v = text_of(
    &server
      .call_tool("stack_lookup", &json!({"query": "vogt"}))
      .await,
  );
  assert_eq!(v["count"], 2);
  assert_eq!(v["stacks"][0]["mutations"], "allowed");
}

#[tokio::test]
async fn env_diff_modes_never_emit_values() {
  let (server, _) = start(policy("", "")).await;
  // Against another stack.
  let v = text_of(
    &server
      .call_tool("env_diff", &json!({"stack": "vogt-dev", "against": {"stack": "vogt-prod"}}))
      .await,
  );
  assert_clean(&v);
  let changed: Vec<_> = v["diff"]["changed"]
    .as_array()
    .unwrap()
    .iter()
    .map(|c| c["name"].as_str().unwrap())
    .collect();
  assert_eq!(changed, ["DB_PASSWORD", "PLAIN"]);

  // Against the env as of the last successful deploy (from Update TOML).
  let v = text_of(
    &server
      .call_tool(
        "env_diff",
        &json!({"stack": "vogt-dev", "against": {"last_successful_deploy": true}}),
      )
      .await,
  );
  assert_clean(&v);
  assert_eq!(v["diff"]["added"][0]["name"], "NEW_AFTER_DEPLOY");
  assert!(v["diff"]["changed"].as_array().unwrap().is_empty());

  // Against supplied fingerprints.
  let fp = names_diff::fingerprint(SECRET_DB);
  let v = text_of(
    &server
      .call_tool(
        "env_diff",
        &json!({"stack": "vogt-dev", "against": {"hashes": {"DB_PASSWORD": fp, "GONE": "sha256:000000000000/1"}}}),
      )
      .await,
  );
  assert_eq!(v["diff"]["removed"][0]["name"], "GONE");
  assert_eq!(v["diff"]["unchanged"], 1);

  // Against a local env file whose values the server never saw before.
  let dir = std::env::temp_dir()
    .join(format!("komodo-mcp-test-{}", std::process::id()));
  std::fs::create_dir_all(&dir).unwrap();
  let file = dir.join("local.env");
  std::fs::write(
    &file,
    format!("DB_PASSWORD={SECRET_LOCAL}\nPLAIN=1\n"),
  )
  .unwrap();
  let v = text_of(
    &server
      .call_tool(
        "env_diff",
        &json!({"stack": "vogt-dev", "against": {"env_file": file.to_str().unwrap()}}),
      )
      .await,
  );
  assert_clean(&v);
  assert_eq!(v["diff"]["changed"][0]["name"], "DB_PASSWORD");
  std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn mutations_refused_when_read_only() {
  let (server, state) = start(policy("", "")).await;
  for (tool, args) in [
    ("deploy_stack", json!({"stack": "vogt-dev"})),
    (
      "write_stack_file",
      json!({"stack": "vogt-dev", "path": "vogt.compose.yml", "content": "x"}),
    ),
  ] {
    let res = server.call_tool(tool, &args).await;
    assert_eq!(res["isError"], true, "{tool}");
    assert!(
      text_of(&res)["error"]
        .as_str()
        .unwrap()
        .contains("not in the mutation allowlist")
    );
  }
  let t = types(&state);
  assert!(!t.iter().any(|t| t == "DeployStack"
    || t == "WriteStackFileContents"
    || t == "RefreshStackCache"));
}

#[tokio::test]
async fn prod_needs_exact_opt_in_even_by_id() {
  let (server, state) = start(policy("*", "")).await;
  for stack in ["vogt-prod", PROD_ID] {
    let res = server
      .call_tool("deploy_stack", &json!({"stack": stack}))
      .await;
    assert_eq!(res["isError"], true);
    assert!(
      text_of(&res)["error"]
        .as_str()
        .unwrap()
        .contains("protected")
    );
  }
  assert!(!types(&state).iter().any(|t| t == "DeployStack"));

  let (server, state) = start(policy("", "vogt-prod")).await;
  let v = text_of(
    &server
      .call_tool("deploy_stack", &json!({"stack": PROD_ID}))
      .await,
  );
  assert_eq!(v["pass"], true);
  assert!(types(&state).iter().any(|t| t == "DeployStack"));
}

#[tokio::test]
async fn write_refreshes_first_and_verifies() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  let content = "services:\n  vogt:\n    image: x@sha256:new\n";
  let res = server
    .call_tool(
      "write_stack_file",
      &json!({"stack": "vogt-dev", "path": "vogt.compose.yml", "content": content, "reason": "bump digest"}),
    )
    .await;
  let v = text_of(&res);
  assert_eq!(res["isError"], false, "{v}");
  assert_clean(&v);
  assert_eq!(v["verified_after_refresh"], true);
  assert_eq!(v["change"]["lines_added"], 1);
  assert_eq!(v["change"]["lines_removed"], 2);
  assert!(!v.to_string().contains("File contents to write"));
  {
    let m = state.lock().unwrap();
    let seq: Vec<_> =
      m.requests.iter().map(|r| r.1.as_str()).collect();
    assert_eq!(
      seq,
      [
        "GetStack",
        "RefreshStackCache",
        "GetStack",
        "WriteStackFileContents",
        "RefreshStackCache",
        "GetStack"
      ]
    );
    let write = m
      .requests
      .iter()
      .find(|r| r.1 == "WriteStackFileContents")
      .unwrap();
    assert_eq!(
      write.2,
      json!({"stack": DEV_ID, "file_path": "vogt.compose.yml", "contents": content})
    );
    assert_eq!(write.3.as_deref(), Some("vogt-session:test"));
  }

  // Identical content: no second write.
  let v = text_of(
    &server
      .call_tool("write_stack_file", &json!({"stack": "vogt-dev", "path": "vogt.compose.yml", "content": content}))
      .await,
  );
  assert_eq!(v["changed"], false);
  let writes = types(&state)
    .iter()
    .filter(|t| *t == "WriteStackFileContents")
    .count();
  assert_eq!(writes, 1);

  // Env files are refused.
  let res = server
    .call_tool(
      "write_stack_file",
      &json!({"stack": "vogt-dev", "path": ".env", "content": "A=1"}),
    )
    .await;
  assert_eq!(res["isError"], true);
}

#[tokio::test]
async fn deploy_failure_returns_clean_tail() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  state.lock().unwrap().deploy_fails = true;
  let v = text_of(
    &server
      .call_tool("deploy_stack", &json!({"stack": "vogt-dev"}))
      .await,
  );
  assert_clean(&v);
  assert_eq!(v["pass"], false);
  assert_eq!(v["completed"], true);
  assert_eq!(v["failure"]["stage"], "Compose Up");
  let tail = v["failure"]["tail"].as_str().unwrap();
  assert!(tail.contains("Error: env DB_PASSWORD=[redacted:DB_PASSWORD] rejected & failed"), "{tail}");
  assert!(!tail.contains("<span"));
  assert!(v.get("health").is_none());
}

#[tokio::test]
async fn deploy_success_reports_health() {
  let (server, _) = start(policy("vogt-dev", "")).await;
  let v = text_of(
    &server
      .call_tool(
        "deploy_stack",
        &json!({"stack": "vogt-dev", "reason": "bump"}),
      )
      .await,
  );
  assert_clean(&v);
  assert_eq!(v["pass"], true);
  assert_eq!(v["duration_secs"], 60);
  assert_eq!(v["health"]["all_ok"], true);
}

#[tokio::test]
async fn health_and_logs_do_not_leak() {
  let (server, _) = start(policy("", "")).await;
  let v = text_of(
    &server
      .call_tool("container_health", &json!({"stack": "vogt-dev"}))
      .await,
  );
  assert_clean(&v);
  assert_eq!(v["services"][0]["health"]["status"], "healthy");
  assert!(!v.to_string().contains("secret.label"));
  let v = text_of(
    &server
      .call_tool(
        "container_logs",
        &json!({"stack": "vogt-dev", "service": "vogt", "tail": 50}),
      )
      .await,
  );
  assert_clean(&v);
  assert_eq!(
    v["stdout"],
    "boot\nconnecting with [redacted:DB_PASSWORD]\nready"
  );
}

#[tokio::test]
async fn read_file_is_scrubbed_and_env_refused() {
  let (server, _) = start(policy("", "")).await;
  let v = text_of(
    &server
      .call_tool(
        "read_stack_file",
        &json!({"stack": "vogt-dev", "path": "vogt.compose.yml"}),
      )
      .await,
  );
  assert_clean(&v);
  assert!(
    v["contents"]
      .as_str()
      .unwrap()
      .contains("[redacted:DB_PASSWORD]")
  );
  let res = server
    .call_tool(
      "read_stack_file",
      &json!({"stack": "vogt-dev", "path": "personal/.env"}),
    )
    .await;
  assert_eq!(res["isError"], true);
}

#[tokio::test]
async fn history_is_names_only_with_actor() {
  let (server, _) = start(policy("", "")).await;
  let v = text_of(
    &server
      .call_tool("stack_history", &json!({"stack": "vogt-dev", "since_last_successful_deploy": true}))
      .await,
  );
  assert_clean(&v);
  assert_eq!(v["reached_last_successful_deploy"], true);
  let ops: Vec<_> = v["updates"]
    .as_array()
    .unwrap()
    .iter()
    .map(|u| u["operation"].as_str().unwrap())
    .collect();
  assert_eq!(
    ops,
    ["WriteStackContents", "UpdateStack", "DeployStack"]
  );
  let cfg =
    &v["updates"][1]["config_diff"]["env"]["config.environment"];
  assert_eq!(cfg["added"][0]["name"], "NEW_AFTER_DEPLOY");
  assert_eq!(v["updates"][0]["written"]["lines"], 1);

  let v = text_of(
    &server
      .call_tool("stack_history", &json!({"stack": "vogt-dev"}))
      .await,
  );
  assert_clean(&v);
  let first_config = &v["updates"][3];
  assert_eq!(first_config["actor"]["actor"], "vogt-session:abc");
  assert_eq!(first_config["actor"]["reason"], "rotate db password");
  let env = &first_config["config_diff"]["env"]["config.environment"];
  assert_eq!(env["changed"][0]["name"], "DB_PASSWORD");
  let added: Vec<_> = env["added"]
    .as_array()
    .unwrap()
    .iter()
    .map(|a| a["name"].as_str().unwrap())
    .collect();
  assert_eq!(added, ["GH_TOKEN", "REF"]);
  assert_eq!(
    env["added"][1]["value"]["reference"],
    "[[infisical://apps/prod/HOMELAB_REF]]"
  );
}

#[tokio::test]
async fn errors_are_scrubbed_and_protocol_works() {
  let (server, _) = start(policy("", "")).await;
  let res = server
    .call_tool("get_stack", &json!({"stack": "nope"}))
    .await;
  assert_eq!(res["isError"], true);
  let res = server.call_tool("no_such_tool", &json!({})).await;
  assert_eq!(res["isError"], true);

  let init = server
    .handle(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}))
    .await
    .unwrap();
  assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
  assert!(
    init["result"]["instructions"]
      .as_str()
      .unwrap()
      .contains("READ-ONLY")
  );
  let list = server
    .handle(
      json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await
    .unwrap();
  let names: Vec<_> = list["result"]["tools"]
    .as_array()
    .unwrap()
    .iter()
    .map(|t| t["name"].as_str().unwrap())
    .collect();
  assert_eq!(names.len(), 9);
  assert!(server.handle(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await.is_none());
  let unknown = server
    .handle(json!({"jsonrpc": "2.0", "id": 3, "method": "x"}))
    .await
    .unwrap();
  assert_eq!(unknown["error"]["code"], -32601);
  let call = server
    .handle(json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "get_stack", "arguments": {"stack": "vogt-prod"}}}))
    .await
    .unwrap();
  assert_clean(&call);
}
