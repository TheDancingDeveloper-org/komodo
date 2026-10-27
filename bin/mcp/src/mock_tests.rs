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
    read::{
      GetStack, GetStackLog, GetUpdate, GetUsername, GetVariable,
      ListUpdates,
    },
    write::{RefreshStackCache, WriteStackFileContents},
  },
  entities::{
    Operation, ResourceTarget, ResourceTargetVariant, SystemCommand,
    Version,
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
    variable::Variable,
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
  /// (endpoint, type, params, x-komodo-actor, x-komodo-reason)
  #[allow(clippy::type_complexity)]
  requests:
    Vec<(String, String, Value, Option<String>, Option<String>)>,
  /// Next UpdateStack writes the stored env as this string instead of the
  /// body that was sent. Consumed once. Used to fail verification.
  store_instead: Option<String>,
  command_store_instead: Option<SystemCommand>,
  /// Next UpdateStack reports this env as prev_toml (a lost update).
  /// Consumed once.
  race_prev: Option<String>,
  command_race_prev: Option<SystemCommand>,
  /// Every UpdateStack reports this env as prev_toml. Not consumed, so a
  /// repair write races too.
  race_prev_always: Option<String>,
  /// GetStack calls so far, used to apply mutate_on_get on a later read.
  get_stack_calls: u64,
  /// After this many GetStack calls (1 = the next one), replace the stored
  /// env before returning. Consumed once.
  mutate_on_get_after: u64,
  /// After the next GetStack, replace the stored env before returning.
  /// Consumed once. Simulates a writer between the two reads.
  mutate_on_get: Option<String>,
  update_seq: u64,
  pending_write: Option<(String, String, String)>,
  deploy_fails: bool,
  get_update_calls: usize,
  variables: HashMap<String, Variable>,
  service_users: Vec<String>,
  /// GetUsername omits `service_user`, like a Core older than K3.
  omit_service_user: bool,
  variable_seq: u64,
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
      swarm_name: String::new(),
      server_id: "srv".into(),
      server_name: String::new(),
      files_on_host: false,
      file_contents: false,
      linked_repo: String::new(),
      linked_repo_name: String::new(),
      git_provider: "repo.indexarr.net".into(),
      repo: s.config.repo.clone(),
      branch: "main".into(),
      repo_link: String::new(),
      state: StackState::Running,
      status: None,
      services: vec![],
      auto_update_all_services: false,
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
    username: "operator".into(),
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
      "[[stack]]\nname = \"vogt-dev\"\n\n[stack.config]\nbranch = \"main\"\nenvironment = \"\"\"\n{env}\"\"\"\n"
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

#[derive(Clone, Copy)]
enum VarOp {
  Create,
  UpdateValue,
  Delete,
}

/// A Variable Update exactly as Core writes it
/// (`bin/core/src/api/write/variable.rs`).
fn push_variable_update(
  state: &Shared,
  op: VarOp,
  name: &str,
  value: &str,
  setter: &str,
) -> String {
  let mut mock = state.lock().unwrap();
  mock.variable_seq += 1;
  let id = format!("dddddddddddddddddddd{:04x}", mock.variable_seq);
  let variable = Variable {
    name: name.into(),
    value: value.into(),
    is_secret: false,
    ..Default::default()
  };
  let (operation, stage, stdout) = match op {
    VarOp::Create => (
      Operation::CreateVariable,
      "Create Variable",
      format!("{variable:#?}"),
    ),
    VarOp::Delete => (
      Operation::DeleteVariable,
      "Delete Variable",
      format!("{variable:#?}"),
    ),
    VarOp::UpdateValue => {
      let old = mock
        .variables
        .get(name)
        .map(|v| v.value.clone())
        .unwrap_or_default();
      (
        Operation::UpdateVariableValue,
        "Update Variable Value",
        format!(
          "<span class=\"text-muted-foreground\">variable</span>: '{name}'\n<span class=\"text-muted-foreground\">from</span>: <span class=\"text-red-500\">{old}</span>\n<span class=\"text-muted-foreground\">to</span>:   <span class=\"text-green-500\">{value}</span>"
        ),
      )
    }
  };
  let update = Update {
    id: id.clone(),
    operation,
    start_ts: chrono::Utc::now().timestamp_millis(),
    success: true,
    status: UpdateStatus::Complete,
    operator: setter.into(),
    target: ResourceTarget::system(),
    logs: vec![log(stage, &stdout, "", true)],
    ..Default::default()
  };
  match op {
    VarOp::Delete => {
      mock.variables.remove(name);
    }
    _ => {
      mock.variables.insert(name.into(), variable);
    }
  }
  mock.update_list.insert(0, update_item(&update));
  mock.updates.insert(id.clone(), update);
  id
}

fn unlock_value(
  entry_stack: &str,
  scopes: &[&str],
  offset_secs: i64,
) -> String {
  let until =
    chrono::Utc::now() + chrono::Duration::seconds(offset_secs);
  json!({
    "stack": entry_stack,
    "until": until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    "scope": scopes,
  })
  .to_string()
}

/// Set an unlock the way a person usually does: UpdateVariableValue on an
/// existing variable, else CreateVariable.
fn install_unlock(
  state: &Shared,
  variable_stack: &str,
  entry_stack: &str,
  scopes: &[&str],
  setter: &str,
  offset_secs: i64,
) -> String {
  let name = crate::unlock::variable_name(variable_stack);
  let exists = state.lock().unwrap().variables.contains_key(&name);
  push_variable_update(
    state,
    if exists {
      VarOp::UpdateValue
    } else {
      VarOp::Create
    },
    &name,
    &unlock_value(entry_stack, scopes, offset_secs),
    setter,
  )
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

fn stack_resource_toml(name: &str, config: &StackConfig) -> String {
  crate::tools::export_stack_resource_toml(name, config)
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
  let reason = headers
    .get("x-komodo-reason")
    .and_then(|v| v.to_str().ok())
    .map(String::from);
  let mut m = state.lock().unwrap();
  m.requests.push((
    endpoint.clone(),
    ty.clone(),
    params.clone(),
    actor,
    reason.clone(),
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
    ("read", "GetVariable") => {
      let p = parse!(GetVariable);
      json!(
        m.variables.get(&p.name).ok_or_else(|| err("no variable"))?
      )
    }
    ("read", "GetUsername") => {
      let p = parse!(GetUsername);
      let mut v = json!({
        "username": format!("user-{}", p.user_id),
        "service_user": m.service_users.contains(&p.user_id),
        "avatar": null,
      });
      if m.omit_service_user {
        v.as_object_mut().unwrap().remove("service_user");
      }
      v
    }
    ("read", "ListStacks") => {
      json!(m.stacks.iter().map(list_item).collect::<Vec<_>>())
    }
    ("read", "GetStack") => {
      let p = parse!(GetStack);
      m.get_stack_calls += 1;
      let due = m.mutate_on_get_after == 0
        || m.get_stack_calls >= m.mutate_on_get_after;
      if due
        && let Some(env) = m.mutate_on_get.take()
        && let Some(s) = m
          .stacks
          .iter_mut()
          .find(|s| s.id == p.stack || s.name == p.stack)
      {
        s.config.environment = env;
      }
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
    ("write", "UpdateStack") => {
      let p = parse!(komodo_client::api::write::UpdateStack);
      let idx = m
        .stacks
        .iter()
        .position(|s| s.id == p.id || s.name == p.id)
        .ok_or_else(|| err("no stack"))?;
      let before = m.stacks[idx].config.clone();
      let mut previous = before.clone();
      let mut stored = before.clone();
      if let Some(sent) = p.config.environment {
        let raced = if m.race_prev_always.is_some() {
          m.race_prev_always.clone()
        } else {
          m.race_prev.take()
        };
        previous.environment =
          raced.unwrap_or_else(|| before.environment.clone());
        stored.environment = m.store_instead.take().unwrap_or(sent);
      }
      if let Some(sent) = p.config.pre_deploy {
        previous.pre_deploy = m
          .command_race_prev
          .take()
          .unwrap_or_else(|| before.pre_deploy.clone());
        stored.pre_deploy =
          m.command_store_instead.take().unwrap_or(sent);
      } else if let Some(sent) = p.config.post_deploy {
        previous.post_deploy = m
          .command_race_prev
          .take()
          .unwrap_or_else(|| before.post_deploy.clone());
        stored.post_deploy =
          m.command_store_instead.take().unwrap_or(sent);
      }
      // Core stores each sent partial field exactly. Raw command and env
      // values remain only in this in-process mock and the Update TOML.
      m.stacks[idx].config = stored.clone();
      m.update_seq += 1;
      let id = format!("cccccccccccccccccccc{:04x}", m.update_seq);
      let stack_id = m.stacks[idx].id.clone();
      let name = m.stacks[idx].name.clone();
      let prev_toml = stack_resource_toml(&name, &previous);
      let current_toml = stack_resource_toml(&name, &stored);
      let diff =
        names_diff::diff_resource_toml(&prev_toml, &current_toml)
          .map(|d| d.render())
          .unwrap_or_else(|e| format!("diff failed: {e}"));

      let reason_text = reason.clone().unwrap_or_default();
      let update = Update {
        id: id.clone(),
        operation: Operation::UpdateStack,
        start_ts: 20_000 + m.update_seq as i64,
        success: true,
        status: UpdateStatus::Complete,
        operator: "user-1".into(),
        target: ResourceTarget::Stack(stack_id),
        prev_toml,
        current_toml,
        logs: vec![
          log(
            "Actor (asserted)",
            &format!(
              "actor: vogt-session:test\nreason: {reason_text}"
            ),
            "",
            true,
          ),
          log("Config diff (names only)", &diff, "", true),
        ],
        ..Default::default()
      };
      m.updates.insert(id, update.clone());
      m.update_list.insert(0, update_item(&update));
      // UpdateStack's response is the Stack, not the Update.
      json!(m.stacks[idx].clone())
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
    unlock_max_ttl: Duration::from_secs(14_400),
    stale_allow_protected: false,
  };
  let api_user = komodo_client::entities::user::User {
    id: "000000000000000000000001".into(),
    username: "komodo-agents".into(),
    enabled: true,
    config: komodo_client::entities::user::UserConfig::Service {
      description: String::new(),
    },
    ..Default::default()
  };
  let server = Server {
    komodo: Komodo::new(&config),
    policy,
    poll: Duration::from_millis(10),
    env_locks: Default::default(),
    api_user: Some(api_user),
    unlock_max_ttl: Duration::from_secs(14_400),
    stale_allow_protected: false,
  };
  (server, state)
}

fn policy(write: &str, allow_protected: &str) -> Policy {
  let _ = allow_protected;
  Policy {
    write: split_list(write),
    protected: split_list("*prod*"),
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
  assert_eq!(v["stacks"][0]["mutations"]["state"], "protected");
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
async fn protected_stack_requires_current_audited_unlock_even_by_id()
{
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

  let (server, state) = start(policy("*", "")).await;
  // vogt_prod and vogt-prod share a variable name; a grant written for
  // vogt_prod must not unlock vogt-prod.
  assert_eq!(
    crate::unlock::variable_name("vogt_prod"),
    "KOMODO_MCP_UNLOCK__VOGT_PROD"
  );
  install_unlock(
    &state,
    "vogt-prod",
    "vogt_prod",
    &["deploy"],
    "human-1",
    300,
  );
  let collision = server
    .call_tool("deploy_stack", &json!({"stack": PROD_ID}))
    .await;
  assert_eq!(collision["isError"], true);
  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["deploy"],
    "human-1",
    300,
  );
  let v = text_of(
    &server
      .call_tool("deploy_stack", &json!({"stack": PROD_ID}))
      .await,
  );
  assert_eq!(v["pass"], true);
  assert!(types(&state).iter().any(|t| t == "DeployStack"));
  let reasons: Vec<_> = state
    .lock()
    .unwrap()
    .requests
    .iter()
    .filter(|(_, ty, _, _, _)| ty == "DeployStack")
    .filter_map(|(_, _, _, _, reason)| reason.clone())
    .collect();
  assert!(reasons.iter().any(|r| r.starts_with("[unlock=")));
}

#[tokio::test]
async fn unlock_scope_expiry_setter_and_reread_are_enforced() {
  let (server, state) = start(policy("*", "")).await;
  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["files"],
    "human-1",
    300,
  );
  let wrong_scope = server
    .call_tool("deploy_stack", &json!({"stack": "vogt-prod"}))
    .await;
  assert!(
    text_of(&wrong_scope)["error"]
      .as_str()
      .unwrap()
      .contains("scope")
  );

  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["deploy"],
    "human-1",
    -1,
  );
  let expired = server
    .call_tool("deploy_stack", &json!({"stack": "vogt-prod"}))
    .await;
  assert!(
    text_of(&expired)["error"]
      .as_str()
      .unwrap()
      .contains("expired")
  );

  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["deploy"],
    "000000000000000000000001",
    300,
  );
  let own = server
    .call_tool("deploy_stack", &json!({"stack": "vogt-prod"}))
    .await;
  assert!(
    text_of(&own)["error"]
      .as_str()
      .unwrap()
      .contains("own API user")
  );

  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["deploy"],
    "service-1",
    300,
  );
  state.lock().unwrap().service_users.push("service-1".into());
  let service = server
    .call_tool("deploy_stack", &json!({"stack": "vogt-prod"}))
    .await;
  assert!(
    text_of(&service)["error"]
      .as_str()
      .unwrap()
      .contains("service user")
  );

  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["deploy"],
    "human-1",
    300,
  );
  let first = server
    .call_tool("deploy_stack", &json!({"stack": "vogt-prod"}))
    .await;
  assert_eq!(first["isError"], false, "{first}");
  state
    .lock()
    .unwrap()
    .variables
    .remove(&crate::unlock::variable_name("vogt-prod"));
  let second = server
    .call_tool("deploy_stack", &json!({"stack": "vogt-prod"}))
    .await;
  assert_eq!(second["isError"], true, "{second}");
}

const API_USER: &str = "000000000000000000000001";

async fn deploy_prod(server: &Server) -> Value {
  server
    .call_tool("deploy_stack", &json!({"stack": "vogt-prod"}))
    .await
}

fn deploy_reason(state: &Shared) -> String {
  state
    .lock()
    .unwrap()
    .requests
    .iter()
    .rfind(|r| r.1 == "DeployStack")
    .and_then(|r| r.4.clone())
    .unwrap()
}

fn error_text(res: &Value) -> String {
  assert_eq!(res["isError"], true, "{res}");
  text_of(res)["error"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn first_time_create_variable_unlock_is_honoured() {
  let (server, state) = start(policy("*", "")).await;
  let name = crate::unlock::variable_name("vogt-prod");
  let id = push_variable_update(
    &state,
    VarOp::Create,
    &name,
    &unlock_value("vogt-prod", &["deploy"], 300),
    "human-1",
  );
  let res = deploy_prod(&server).await;
  assert_eq!(res["isError"], false, "{res}");
  let reason = deploy_reason(&state);
  assert!(reason.starts_with(&format!("[unlock={id} ")), "{reason}");
}

/// The review's attack: a person grants `files`; the MCP's own API user
/// then recreates the variable with `deploy`. The newest Variable update
/// is the agent's, so the setter check refuses it.
#[tokio::test]
async fn agent_cannot_self_grant_by_recreating_the_variable() {
  let (server, state) = start(policy("*", "")).await;
  let name = crate::unlock::variable_name("vogt-prod");
  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["files"],
    "human-1",
    300,
  );
  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["files"],
    "human-1",
    300,
  );
  push_variable_update(
    &state,
    VarOp::Create,
    &name,
    &unlock_value("vogt-prod", &["deploy"], 300),
    API_USER,
  );
  assert!(
    error_text(&deploy_prod(&server).await).contains("own API user")
  );

  // The same through Delete then Create.
  push_variable_update(&state, VarOp::Delete, &name, "", API_USER);
  push_variable_update(
    &state,
    VarOp::Create,
    &name,
    &unlock_value("vogt-prod", &["deploy"], 300),
    API_USER,
  );
  assert!(
    error_text(&deploy_prod(&server).await).contains("own API user")
  );
  assert!(!types(&state).iter().any(|t| t == "DeployStack"));
}

#[tokio::test]
async fn stale_grant_does_not_survive_delete_and_recreate() {
  let (server, state) = start(policy("*", "")).await;
  let name = crate::unlock::variable_name("vogt-prod");
  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["deploy"],
    "human-1",
    300,
  );
  push_variable_update(&state, VarOp::Delete, &name, "", "human-1");
  // Recreated outside any audited update (e.g. a restored database).
  let value = unlock_value("vogt-prod", &["deploy"], 300);
  state.lock().unwrap().variables.insert(
    name.clone(),
    Variable {
      name: name.clone(),
      value,
      ..Default::default()
    },
  );
  assert!(
    error_text(&deploy_prod(&server).await)
      .contains("DeleteVariable")
  );
}

#[tokio::test]
async fn unlock_value_must_equal_the_newest_audit_update() {
  let (server, state) = start(policy("*", "")).await;
  let name = crate::unlock::variable_name("vogt-prod");
  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["files"],
    "human-1",
    300,
  );
  // The value changes with no Update recording it.
  state
    .lock()
    .unwrap()
    .variables
    .get_mut(&name)
    .unwrap()
    .value = unlock_value("vogt-prod", &["deploy"], 300);
  assert!(
    error_text(&deploy_prod(&server).await)
      .contains("does not match")
  );
  assert!(!types(&state).iter().any(|t| t == "DeployStack"));
}

#[tokio::test]
async fn unlocks_unavailable_when_get_user_failed() {
  let (mut server, state) = start(policy("*", "")).await;
  server.api_user = None;
  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["deploy"],
    "human-1",
    300,
  );
  assert!(
    error_text(&deploy_prod(&server).await).contains("unavailable")
  );
  // Non-protected stacks still work.
  let dev = server
    .call_tool("deploy_stack", &json!({"stack": "vogt-dev"}))
    .await;
  assert_eq!(dev["isError"], false, "{dev}");
}

#[tokio::test]
async fn unknown_service_user_flag_is_refused() {
  let (server, state) = start(policy("*", "")).await;
  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["deploy"],
    "human-1",
    300,
  );
  state.lock().unwrap().omit_service_user = true;
  assert!(
    error_text(&deploy_prod(&server).await)
      .contains("did not report")
  );
}

#[tokio::test]
async fn forged_unlock_reason_is_not_reported_as_an_unlock() {
  let (server, state) = start(policy("*", "")).await;
  let res = server
    .call_tool(
      "deploy_stack",
      &json!({"stack": "vogt-dev", "reason": "[unlock=fake until=x] hi"}),
    )
    .await;
  assert_eq!(res["isError"], false, "{res}");
  let reason = deploy_reason(&state);
  assert!(reason.starts_with("(unverified) "), "{reason}");
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
  assert!(v["unlocks"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn history_lists_unlocks_and_stamped_uses() {
  let (server, state) = start(policy("*", "")).await;
  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["files"],
    "human-1",
    300,
  );
  install_unlock(
    &state,
    "vogt-prod",
    "vogt-prod",
    &["deploy"],
    "human-1",
    300,
  );
  let applied = server
    .call_tool(
      "deploy_stack",
      &json!({"stack": "vogt-prod", "reason": "ship under unlock"}),
    )
    .await;
  assert_eq!(applied["isError"], false, "{applied}");
  let v = text_of(
    &server
      .call_tool("stack_history", &json!({"stack": "vogt-prod"}))
      .await,
  );
  assert_clean(&v);
  assert_eq!(v["unlocks"][0]["operation"], "unlock-changed");
  assert_eq!(v["unlocks"][0]["scope"][0], "deploy");
  // Each entry is read from its own log, not the current value.
  assert_eq!(v["unlocks"][1]["operation"], "unlock-set");
  assert_eq!(v["unlocks"][1]["scope"][0], "files");
  assert!(v["unlocks"][0]["until"].as_str().unwrap().ends_with('Z'));
  let reason = state
    .lock()
    .unwrap()
    .requests
    .iter()
    .find(|(_, ty, _, _, _)| ty == "DeployStack")
    .and_then(|(_, _, _, _, reason)| reason.clone())
    .unwrap();
  let id = reason
    .strip_prefix("[unlock=")
    .and_then(|rest| rest.split_once(" until="))
    .map(|(id, _)| id.to_string())
    .unwrap();
  assert_eq!(id, v["unlocks"][0]["update_id"].as_str().unwrap());
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
  assert_eq!(names.len(), 11);
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

const REF: &str = "[[infisical://infrastructure/prod/SOME_KEY]]";

fn rich_env() -> String {
  // Six parsed keys, plus a comment, an export prefix, a quoted multi-line
  // value and a line parse_env cannot keep.
  "\
# keep this comment
ALPHA=one
export BETA=two
GAMMA=\"line-a
line-b\"
DELTA=four # trailing note
- EPSILON=five
ZETA=six
this line is not a pair
"
  .to_string()
}

fn set_dev_env(state: &Shared, env: &str) {
  let mut m = state.lock().unwrap();
  m.stacks
    .iter_mut()
    .find(|s| s.name == "vogt-dev")
    .unwrap()
    .config
    .environment = env.to_string();
}

fn dev_env(state: &Shared) -> String {
  state
    .lock()
    .unwrap()
    .stacks
    .iter()
    .find(|s| s.name == "vogt-dev")
    .unwrap()
    .config
    .environment
    .clone()
}

fn update_stack_count(state: &Shared) -> usize {
  state
    .lock()
    .unwrap()
    .requests
    .iter()
    .filter(|r| r.1 == "UpdateStack")
    .count()
}

fn reasons(state: &Shared) -> Vec<Option<String>> {
  state
    .lock()
    .unwrap()
    .requests
    .iter()
    .filter(|r| r.1 == "UpdateStack")
    .map(|r| r.4.clone())
    .collect()
}

fn call_env(
  server: &Server,
  extra: serde_json::Value,
) -> impl std::future::Future<Output = Value> + '_ {
  let mut args = json!({
    "stack": "vogt-dev",
    "name": "BETA",
    "op": "replace",
    "reference": REF,
    "reason": "rotate one key",
  });
  if let (Some(obj), Some(more)) =
    (args.as_object_mut(), extra.as_object())
  {
    for (k, v) in more {
      obj.insert(k.clone(), v.clone());
    }
  }
  async move { server.call_tool("edit_stack_env", &args).await }
}

fn call_command(
  server: &Server,
  extra: serde_json::Value,
) -> impl std::future::Future<Output = Value> + '_ {
  let mut args = json!({
    "stack": "vogt-dev",
    "which": "pre_deploy",
    "op": "append",
    "command": "echo appended",
    "reason": "edit test command",
  });
  if let (Some(obj), Some(more)) =
    (args.as_object_mut(), extra.as_object())
  {
    for (key, value) in more {
      obj.insert(key.clone(), value.clone());
    }
  }
  async move { server.call_tool("edit_stack_command", &args).await }
}

fn set_dev_command(state: &Shared, command: SystemCommand) {
  state
    .lock()
    .unwrap()
    .stacks
    .iter_mut()
    .find(|stack| stack.name == "vogt-dev")
    .unwrap()
    .config
    .pre_deploy = command;
}

fn dev_command(state: &Shared) -> SystemCommand {
  state
    .lock()
    .unwrap()
    .stacks
    .iter()
    .find(|stack| stack.name == "vogt-dev")
    .unwrap()
    .config
    .pre_deploy
    .clone()
}

/// Test 1: one key changes; every other byte and the rest of the config stay.
#[tokio::test]
async fn edit_env_one_key_others_byte_identical() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  let before = rich_env();
  set_dev_env(&state, &before);
  let rest_before = {
    let m = state.lock().unwrap();
    let s = m.stacks.iter().find(|s| s.name == "vogt-dev").unwrap();
    let mut v = serde_json::to_value(&s.config).unwrap();
    v.as_object_mut().unwrap().remove("environment");
    names_diff::fingerprint(&v.to_string())
  };
  let res = call_env(&server, json!({})).await;
  assert_eq!(res["isError"], false, "{res}");
  let v = text_of(&res);
  assert_clean(&v);
  let text = res["content"][0]["text"].as_str().unwrap();
  assert!(!text.contains("two"));
  assert!(!text.contains("line-a"));
  let after = dev_env(&state);
  let spans = names_diff::env_spans(&before);
  let beta = spans.iter().find(|s| s.name == "BETA").unwrap();
  let mut expect = String::new();
  expect.push_str(&before[..beta.start]);
  expect.push_str("BETA=");
  expect.push_str(REF);
  expect.push_str(&before[beta.end..]);
  assert_eq!(
    after, expect,
    "splice was not byte-identical outside BETA"
  );
  assert!(after.contains("# keep this comment"));
  assert!(after.contains("this line is not a pair"));
  assert!(after.contains("line-a\nline-b"));
  let others_before = names_diff::parse_env(&before)
    .entries
    .into_iter()
    .filter(|e| e.name != "BETA")
    .map(|e| (e.name, names_diff::fingerprint(&e.value)))
    .collect::<Vec<_>>();
  let others_after = names_diff::parse_env(&after)
    .entries
    .into_iter()
    .filter(|e| e.name != "BETA")
    .map(|e| (e.name, names_diff::fingerprint(&e.value)))
    .collect::<Vec<_>>();
  assert_eq!(others_before, others_after);
  let rest_after = {
    let m = state.lock().unwrap();
    let s = m.stacks.iter().find(|s| s.name == "vogt-dev").unwrap();
    let mut v = serde_json::to_value(&s.config).unwrap();
    v.as_object_mut().unwrap().remove("environment");
    names_diff::fingerprint(&v.to_string())
  };
  assert_eq!(rest_before, rest_after);
  assert_eq!(v["changed"], true);
  assert_eq!(v["diff"]["changed"][0]["name"], "BETA");
  assert_eq!(update_stack_count(&state), 1);
  assert!(types(&state).iter().all(|t| t != "DeployStack"));
}

/// Test 2: a non-reference is refused, not echoed, and nothing is written.
#[tokio::test]
async fn edit_env_refuses_literals_without_echo() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  let before = dev_env(&state);
  let token = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";
  let bad = [
    "abc",
    &format!("\"{REF}\""),
    &format!("{REF}x"),
    "[[MY_VAR]]",
    token,
  ];
  for input in bad {
    let res = call_env(
      &server,
      json!({"reference": input, "name": "NEWK", "op": "add"}),
    )
    .await;
    assert_eq!(res["isError"], true, "{input}: {res}");
    let text = res["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("literal values cannot be set"));
    assert!(!text.contains(input), "echoed input in {text}");
    if input == token {
      assert!(!text.contains("ghp_"));
    }
  }
  assert_eq!(dev_env(&state), before);
  assert_eq!(update_stack_count(&state), 0);
}

/// Test 6: the reason header is required and reaches Core.
#[tokio::test]
async fn edit_env_reason_is_required_and_stamped() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  set_dev_env(&state, &rich_env());
  let missing = server
    .call_tool(
      "edit_stack_env",
      &json!({
        "stack": "vogt-dev",
        "name": "BETA",
        "op": "replace",
        "reference": REF,
      }),
    )
    .await;
  assert_eq!(missing["isError"], true);
  let text = missing["content"][0]["text"].as_str().unwrap();
  assert!(text.contains("missing string argument `reason`"));
  assert_eq!(update_stack_count(&state), 0);

  let res = call_env(
    &server,
    json!({"reason": "because the design says so"}),
  )
  .await;
  assert_eq!(res["isError"], false, "{res}");
  assert_eq!(
    reasons(&state),
    vec![Some("because the design says so".into())]
  );
}

/// Test 7: dry_run returns the names-only diff and writes nothing.
#[tokio::test]
async fn edit_env_dry_run_does_not_write() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  let before = rich_env();
  set_dev_env(&state, &before);
  let res = call_env(&server, json!({"dry_run": true})).await;
  assert_eq!(res["isError"], false, "{res}");
  let v = text_of(&res);
  assert_eq!(v["dry_run"], true);
  assert_eq!(v["changed"], true);
  assert_eq!(v["diff"]["changed"][0]["name"], "BETA");
  assert!(
    v["base_fingerprint"]
      .as_str()
      .unwrap()
      .starts_with("sha256:")
  );
  assert_eq!(dev_env(&state), before);
  assert_eq!(update_stack_count(&state), 0);
}

/// Test 8: missing, duplicate and already-present keys are specific errors.
#[tokio::test]
async fn edit_env_key_errors_are_specific() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  set_dev_env(&state, "A=1\nB=2\nA=3\n");
  let missing =
    call_env(&server, json!({"name": "NOPE", "op": "replace"})).await;
  assert!(
    text_of_err(&missing).contains("key NOPE is missing"),
    "{missing}"
  );
  let ambiguous =
    call_env(&server, json!({"name": "A", "op": "replace"})).await;
  let msg = text_of_err(&ambiguous);
  assert!(msg.contains("ambiguous: 2 entries named A"), "{msg}");
  let exists =
    call_env(&server, json!({"name": "B", "op": "add"})).await;
  assert!(
    text_of_err(&exists).contains("key B already exists"),
    "{exists}"
  );
  assert_eq!(update_stack_count(&state), 0);
}

fn text_of_err(result: &Value) -> String {
  text_of(result)["error"].as_str().unwrap().to_string()
}

/// Test 9: a change between the two reads is a conflict and writes nothing.
#[tokio::test]
async fn edit_env_conflict_when_env_moves_before_write() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  set_dev_env(&state, &rich_env());
  // The first GetStack returns the fixture. The re-check GetStack then
  // observes another writer. Refresh does not call GetStack, so the
  // second GetStack is the re-check.
  {
    let mut m = state.lock().unwrap();
    m.mutate_on_get = Some("ALPHA=changed\n".into());
    // fetch_mutable already consumed GetStack #1. The post-refresh
    // read is #2; the re-check is #3.
    m.mutate_on_get_after = 3;
  }
  let res = call_env(&server, json!({})).await;
  assert_eq!(res["isError"], true, "{res}");
  assert!(text_of_err(&res).contains("conflict"));
  assert_eq!(update_stack_count(&state), 0);
  assert_eq!(dev_env(&state), "ALPHA=changed\n");
}

/// §5 single repair is NOT DONE. A detected lost update is refused and
/// no second write is sent. The first UpdateStack has already landed
/// (Core applied it); this call does not try to repair it.
#[tokio::test]
async fn edit_env_lost_update_is_refused() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  let before = rich_env();
  set_dev_env(&state, &before);
  let raced = format!("{before}OMEGA=kept\n");
  state.lock().unwrap().race_prev = Some(raced);
  let res = call_env(&server, json!({})).await;
  assert_eq!(res["isError"], true, "{res}");
  let msg = text_of_err(&res);
  assert!(msg.contains("concurrent writers"), "{msg}");
  assert_eq!(update_stack_count(&state), 1);
}

#[tokio::test]
async fn edit_env_second_race_stops() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  let before = rich_env();
  set_dev_env(&state, &before);
  state.lock().unwrap().race_prev_always =
    Some(format!("{before}OTHER=1\n"));
  let res = call_env(&server, json!({})).await;
  assert_eq!(res["isError"], true, "{res}");
  let msg = text_of_err(&res);
  assert!(msg.contains("concurrent writers"), "{msg}");
  // Each attempt sees a fresh race and stops. No repair write.
  assert_eq!(update_stack_count(&state), 1);
}

/// Test 11: stored env that is not the splice fails verification.
#[tokio::test]
async fn edit_env_verification_mismatch() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  set_dev_env(&state, &rich_env());
  state.lock().unwrap().store_instead =
    Some("NOT=the-splice\n".into());
  let res = call_env(&server, json!({})).await;
  assert_eq!(res["isError"], true, "{res}");
  let msg = text_of_err(&res);
  assert!(msg.contains("verification failed"), "{msg}");
  assert_eq!(update_stack_count(&state), 1);
  assert!(types(&state).iter().all(|t| t != "DeployStack"));
}

/// First add to an empty env: Core omits both empty environment assignments.
#[tokio::test]
async fn edit_env_adds_reference_to_empty_environment() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  set_dev_env(&state, "");
  let res = call_env(
    &server,
    json!({
      "name": "FIRST",
      "op": "add",
      "reference": REF,
      "reason": "first env key",
    }),
  )
  .await;
  assert_eq!(res["isError"], false, "{res}");
  assert_eq!(dev_env(&state), format!("FIRST={REF}\n"));
  assert_eq!(update_stack_count(&state), 1);
}

/// Env half of test 17: add the sccache reference; do not deploy.
#[tokio::test]
async fn edit_env_adds_sccache_reference_without_deploy() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  set_dev_env(&state, "PLAIN=1\n");
  {
    let mut m = state.lock().unwrap();
    let s =
      m.stacks.iter_mut().find(|s| s.name == "vogt-dev").unwrap();
    s.config.pre_deploy = komodo_client::entities::SystemCommand {
      path: "sh".into(),
      command: "set -e\necho one\necho two".into(),
      shell_mode: false,
    };
  }
  let reference =
    "[[infisical://infrastructure/prod/SCCACHE_DIST_CLIENT_TOKEN]]";
  let res = server
    .call_tool(
      "edit_stack_env",
      &json!({
        "stack": "vogt-dev",
        "name": "SCCACHE_DIST_CLIENT_TOKEN",
        "op": "add",
        "reference": reference,
        "reason": "L3 env half",
      }),
    )
    .await;
  assert_eq!(res["isError"], false, "{res}");
  let stored = dev_env(&state);
  assert!(
    stored
      .contains(&format!("SCCACHE_DIST_CLIENT_TOKEN={reference}"))
  );
  assert!(stored.starts_with("PLAIN=1\n"));
  assert!(types(&state).iter().all(|t| t != "DeployStack"));
  let m = state.lock().unwrap();
  let s = m.stacks.iter().find(|s| s.name == "vogt-dev").unwrap();
  assert_eq!(
    s.config.pre_deploy.command,
    "set -e\necho one\necho two"
  );
}

/// Protected stacks stay refused by the existing gate.
#[tokio::test]
async fn edit_env_protected_stack_still_refused() {
  let (server, state) = start(policy("vogt-*", "")).await;
  let before = {
    let m = state.lock().unwrap();
    m.stacks
      .iter()
      .find(|s| s.name == "vogt-prod")
      .unwrap()
      .config
      .environment
      .clone()
  };
  // prod matches *prod* and is not opted in.
  let res = server
    .call_tool(
      "edit_stack_env",
      &json!({
        "stack": "vogt-prod",
        "name": "PLAIN",
        "op": "replace",
        "reference": REF,
        "reason": "should not",
      }),
    )
    .await;
  assert_eq!(res["isError"], true);
  assert!(text_of_err(&res).contains("protected"));
  let after = {
    let m = state.lock().unwrap();
    m.stacks
      .iter()
      .find(|s| s.name == "vogt-prod")
      .unwrap()
      .config
      .environment
      .clone()
  };
  assert_eq!(after, before);
  assert_eq!(update_stack_count(&state), 0);
}

/// Remove strips the entry, its prefix and its newline. Fake values only.
#[tokio::test]
async fn edit_env_remove_strips_prefix_and_newline() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  set_dev_env(&state, "KEEP=1\nexport GONE=old\nTAIL=3\n");
  let res =
    call_env(&server, json!({"name": "GONE", "op": "remove"})).await;
  assert_eq!(res["isError"], false, "{res}");
  assert_eq!(dev_env(&state), "KEEP=1\nTAIL=3\n");
  assert_eq!(update_stack_count(&state), 1);
}

/// if_base matches the whole-env fingerprint, and a mismatch writes nothing.
#[tokio::test]
async fn edit_env_if_base_match_and_mismatch() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  let env = rich_env();
  set_dev_env(&state, &env);
  let fp = names_diff::fingerprint(&env);
  let bad = call_env(
    &server,
    json!({"if_base": "0000000000000000000000000000000000000000000000000000000000000000"}),
  )
  .await;
  assert_eq!(bad["isError"], true, "{bad}");
  assert!(text_of_err(&bad).contains("if_base"), "{bad}");
  assert_eq!(update_stack_count(&state), 0);
  assert_eq!(dev_env(&state), env);
  let ok = call_env(&server, json!({"if_base": fp})).await;
  assert_eq!(ok["isError"], false, "{ok}");
  assert_eq!(update_stack_count(&state), 1);
}

/// Replacing a literal reports was_literal and does not keep the old value.
#[tokio::test]
async fn edit_env_replace_literal_reports_was_literal() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  set_dev_env(&state, "PW=not-a-reference\nKEEP=1\n");
  let res =
    call_env(&server, json!({"name": "PW", "op": "replace"})).await;
  assert_eq!(res["isError"], false, "{res}");
  let body = text_of(&res);
  assert_eq!(body["diff"]["changed"][0]["name"], "PW", "{body}");
  assert!(
    body["diff"]["changed"][0]["before"]["fingerprint"].is_string(),
    "{body}"
  );
  let stored = dev_env(&state);
  assert!(stored.contains(&format!("PW={REF}\n")), "{stored}");
  assert!(!stored.contains("not-a-reference"), "{stored}");
  assert!(stored.contains("KEEP=1\n"));
}

/// A `#` inside a quoted literal is part of the value, not a comment.
/// Fake values only.
#[tokio::test]
async fn edit_env_replace_quoted_hash_does_not_keep_old_literal() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  set_dev_env(&state, "PW=\"abc #s3cret more\"\nKEEP=1\n");
  let res =
    call_env(&server, json!({"name": "PW", "op": "replace"})).await;
  assert_eq!(res["isError"], false, "{res}");
  let stored = dev_env(&state);
  assert!(!stored.contains("s3cret"), "{stored}");
  assert!(stored.contains(&format!("PW={REF}\n")), "{stored}");
  assert!(stored.contains("KEEP=1\n"), "{stored}");
  assert_eq!(stored.lines().count(), 2, "{stored}");
}

/// A backslash in a value must not look like a lost update. Core's export
/// does not escape `\\`, so the check compares both sides after the same
/// render. Fake values only. A line ending in `\\` is included.
#[tokio::test]
async fn edit_env_backslash_is_not_a_false_race() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  set_dev_env(&state, "RE=a\\.b\nTRAIL=end\\\nKEEP=1\n");
  let res =
    call_env(&server, json!({"name": "KEEP", "op": "replace"})).await;
  assert_eq!(res["isError"], false, "{res}");
  let stored = dev_env(&state);
  assert!(stored.contains("RE=a\\.b\n"), "{stored}");
  assert!(stored.contains("TRAIL=end\\\n"), "{stored}");
  assert!(stored.contains(&format!("KEEP={REF}\n")), "{stored}");
}

/// Test 12: append keeps path and shell_mode, and never returns old text.
#[tokio::test]
async fn edit_command_append_keeps_metadata_without_old_text() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  set_dev_command(
    &state,
    SystemCommand {
      path: "/srv/vogt".into(),
      command: "old command that must stay private\n".into(),
      shell_mode: true,
    },
  );
  let response = call_command(&server, json!({})).await;
  assert_eq!(response["isError"], false, "{response}");
  let body = text_of(&response);
  assert_eq!(body["path"], "/srv/vogt");
  assert_eq!(body["shell_mode"], true);
  assert_eq!(body["diff"]["appended_lines"], 1);
  assert_eq!(body["appended"], "echo appended");
  let rendered = response.to_string();
  assert!(!rendered.contains("old command"), "{rendered}");
  assert_eq!(
    dev_command(&state),
    SystemCommand {
      path: "/srv/vogt".into(),
      command: "old command that must stay private\necho appended\n"
        .into(),
      shell_mode: true,
    }
  );
}

#[tokio::test]
async fn edit_command_append_to_empty_field_sets_path() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  set_dev_command(&state, SystemCommand::default());
  let response = call_command(
    &server,
    json!({"path": "/srv", "command": "echo appended"}),
  )
  .await;
  assert_eq!(response["isError"], false, "{response}");
  assert_eq!(
    dev_command(&state),
    SystemCommand {
      path: "/srv".into(),
      command: "echo appended\n".into(),
      shell_mode: false,
    }
  );
}

/// Test 13: replace requires the current command fingerprint.
#[tokio::test]
async fn edit_command_replace_requires_matching_fingerprint() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  let current = SystemCommand {
    path: "sh".into(),
    command: "echo old\n".into(),
    shell_mode: false,
  };
  set_dev_command(&state, current.clone());
  let missing = call_command(
    &server,
    json!({"op": "replace", "command": "echo new"}),
  )
  .await;
  assert_eq!(missing["isError"], true, "{missing}");
  assert!(
    text_of_err(&missing).contains("if_fingerprint is required")
  );
  let stale = call_command(
    &server,
    json!({
      "op": "replace",
      "command": "echo new",
      "if_fingerprint": names_diff::fingerprint("other"),
    }),
  )
  .await;
  assert_eq!(stale["isError"], true, "{stale}");
  assert!(text_of_err(&stale).contains("conflict"));
  assert_eq!(dev_command(&state), current);
  assert_eq!(update_stack_count(&state), 0);
  let matching = call_command(
    &server,
    json!({
      "op": "replace",
      "command": "echo new",
      "path": "/tmp",
      "if_fingerprint": names_diff::fingerprint("echo old\n"),
    }),
  )
  .await;
  assert_eq!(matching["isError"], false, "{matching}");
  assert_eq!(dev_command(&state).command, "echo new\n");
  assert_eq!(dev_command(&state).path, "/tmp");

  let cleared = call_command(
    &server,
    json!({
      "op": "replace",
      "command": "",
      "if_fingerprint": names_diff::fingerprint("echo new\n"),
    }),
  )
  .await;
  assert_eq!(cleared["isError"], false, "{cleared}");
  assert_eq!(dev_command(&state).command, "");

  let empty = call_command(
    &server,
    json!({
      "op": "replace",
      "command": "echo restored",
      "if_fingerprint": "",
    }),
  )
  .await;
  assert_eq!(empty["isError"], false, "{empty}");
  assert_eq!(dev_command(&state).command, "echo restored\n");
}

/// Test 14: known env values and token-shaped literals are refused silently.
#[tokio::test]
async fn edit_command_refuses_literal_secrets_without_echoing() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  for literal in [SECRET_DB, SECRET_GH] {
    let response = call_command(
      &server,
      json!({"command": format!("echo {literal}")}),
    )
    .await;
    assert_eq!(response["isError"], true, "{response}");
    let text = response.to_string();
    assert!(
      text.contains("command contains a literal secret"),
      "{text}"
    );
    assert!(!text.contains(literal), "{text}");
  }
  let path = call_command(
    &server,
    json!({"path": format!("/tmp/{SECRET_DB}")}),
  )
  .await;
  assert_eq!(path["isError"], true, "{path}");
  assert!(!path.to_string().contains(SECRET_DB), "{path}");
  assert_eq!(update_stack_count(&state), 0);
}

#[tokio::test]
async fn edit_command_protected_stack_still_refused() {
  let (server, state) = start(policy("vogt-*", "")).await;
  let response = server
    .call_tool(
      "edit_stack_command",
      &json!({
        "stack": "vogt-prod",
        "which": "pre_deploy",
        "op": "append",
        "command": "echo no",
        "reason": "protected test",
      }),
    )
    .await;
  assert_eq!(response["isError"], true, "{response}");
  assert_eq!(update_stack_count(&state), 0);
}

#[tokio::test]
async fn edit_command_empty_path_is_not_a_false_race() {
  for old in ["echo stored\n", "sed 's/\\./x/'\n"] {
    let (server, state) = start(policy("vogt-dev", "")).await;
    set_dev_command(
      &state,
      SystemCommand {
        path: String::new(),
        command: old.into(),
        shell_mode: false,
      },
    );
    let response = call_command(&server, json!({})).await;
    assert_eq!(response["isError"], false, "{old}: {response}");
    assert_eq!(dev_command(&state).path, "");
    assert_eq!(update_stack_count(&state), 1);
  }
}

#[tokio::test]
async fn edit_command_backslashes_are_not_a_false_race_or_leak() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  let old = "sed 's/\\./x/'\necho continue && \\\n  echo done\n";
  set_dev_command(
    &state,
    SystemCommand {
      path: "sh".into(),
      command: old.into(),
      shell_mode: false,
    },
  );
  let response = call_command(&server, json!({})).await;
  assert_eq!(response["isError"], false, "{response}");
  assert!(!response.to_string().contains("sed"), "{response}");
  assert_eq!(update_stack_count(&state), 1);
}

#[tokio::test]
async fn edit_command_detects_race_and_verification_mismatch() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  let current = SystemCommand {
    path: "sh".into(),
    command: "echo old && \\\n  echo continued\nsed 's/\\./x/'\n"
      .into(),
    shell_mode: false,
  };
  set_dev_command(&state, current.clone());
  state.lock().unwrap().command_race_prev = Some(SystemCommand {
    command: "echo raced\n".into(),
    ..current.clone()
  });
  let raced = call_command(&server, json!({})).await;
  assert_eq!(raced["isError"], true, "{raced}");
  assert!(text_of_err(&raced).contains("concurrent writers"));

  set_dev_command(&state, current.clone());
  state.lock().unwrap().command_store_instead = Some(SystemCommand {
    command: "echo wrong\n".into(),
    ..current
  });
  let mismatch = call_command(&server, json!({})).await;
  assert_eq!(mismatch["isError"], true, "{mismatch}");
  assert!(text_of_err(&mismatch).contains("verification failed"));
}

/// Command half of test 17: append the four-line render step without deploy.
#[tokio::test]
async fn edit_command_appends_l3_render_step_without_deploy() {
  let (server, state) = start(policy("vogt-dev", "")).await;
  let old = "set -e\necho one\necho two";
  set_dev_command(
    &state,
    SystemCommand {
      path: "sh".into(),
      command: format!("{old}\n"),
      shell_mode: false,
    },
  );
  let render = "umask 077\nSCCACHE_DIST_CLIENT_TOKEN=\"$(sed -n 's/^SCCACHE_DIST_CLIENT_TOKEN=//p' .env)\" && test -n \"$SCCACHE_DIST_CLIENT_TOKEN\" && \\\n  SCCACHE_DIST_CLIENT_TOKEN=\"$SCCACHE_DIST_CLIENT_TOKEN\" awk '{ gsub(/@SCCACHE_DIST_CLIENT_TOKEN@/, ENVIRON[\"SCCACHE_DIST_CLIENT_TOKEN\"]) } 1' sccache.conf.tmpl > sccache.conf\nchown 1000:1000 sccache.conf && chmod 600 sccache.conf";
  let response =
    call_command(&server, json!({"command": render})).await;
  assert_eq!(response["isError"], false, "{response}");
  assert_eq!(
    dev_command(&state).command,
    format!("{old}\n{render}\n")
  );
  assert!(types(&state).iter().all(|kind| kind != "DeployStack"));

  let repeat =
    call_command(&server, json!({"command": render})).await;
  assert_eq!(repeat["isError"], false, "{repeat}");
  assert_eq!(text_of(&repeat)["changed"], false);
  assert_eq!(update_stack_count(&state), 1);
}
