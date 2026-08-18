//! Configuration for the Infisical secret provider.
//!
//! Deliberately read from the process environment rather than from
//! [`komodo_client::entities::config::core::CoreConfig`]. Keeping the
//! configuration out of the shared config structs means this fork does not
//! touch `client/core/rs/src/entities/config/core.rs`, `bin/core/src/config.rs`
//! or `config/core.config.toml` — the three highest-churn config files
//! upstream — which is what keeps the patch series cheap to rebase onto each
//! new Komodo release.

use std::{env, fs, time::Duration};

use anyhow::{Context, anyhow, bail};

pub const ENV_ENABLED: &str = "KOMODO_INFISICAL_ENABLED";
pub const ENV_URL: &str = "KOMODO_INFISICAL_URL";
pub const ENV_CLIENT_ID: &str = "KOMODO_INFISICAL_CLIENT_ID";
pub const ENV_CLIENT_SECRET: &str = "KOMODO_INFISICAL_CLIENT_SECRET";
pub const ENV_PROJECTS: &str = "KOMODO_INFISICAL_PROJECTS";
pub const ENV_ENVIRONMENTS: &str = "KOMODO_INFISICAL_ENVIRONMENTS";
pub const ENV_SECRET_PATH: &str = "KOMODO_INFISICAL_SECRET_PATH";
pub const ENV_CACHE_TTL: &str = "KOMODO_INFISICAL_CACHE_TTL_SECONDS";
pub const ENV_STALE_MAX: &str = "KOMODO_INFISICAL_STALE_MAX_SECONDS";
pub const ENV_TIMEOUT: &str = "KOMODO_INFISICAL_TIMEOUT_SECONDS";

const DEFAULT_ENVIRONMENTS: &str = "prod";
const DEFAULT_SECRET_PATH: &str = "/";
const DEFAULT_CACHE_TTL_SECONDS: u64 = 300;
const DEFAULT_STALE_MAX_SECONDS: u64 = 3600;
const DEFAULT_TIMEOUT_SECONDS: u64 = 15;

/// One Infisical project/environment pair to load secrets from.
///
/// `alias` is the short, stable name used in interpolation tokens
/// (`[[infisical://<alias>/<environment>/<KEY>]]`). It is intentionally
/// decoupled from the Infisical project *slug*, which carries a random
/// suffix (`apps-lj-ns`) that would be miserable to write into stack files
/// and would change if the project were recreated.
#[derive(Debug, Clone)]
pub struct Scope {
  pub alias: String,
  pub project_id: String,
  pub environment: String,
}

#[derive(Debug, Clone)]
pub struct InfisicalConfig {
  pub url: String,
  pub client_id: String,
  pub client_secret: String,
  pub scopes: Vec<Scope>,
  pub secret_path: String,
  pub cache_ttl: Duration,
  pub stale_max: Duration,
  pub timeout: Duration,
}

/// Whether the provider is switched on. Absent or unparseable means off, so
/// an unmodified Komodo Core environment behaves exactly like upstream.
pub fn enabled() -> bool {
  env::var(ENV_ENABLED)
    .ok()
    .map(|v| {
      matches!(
        v.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
      )
    })
    .unwrap_or(false)
}

/// Read a value from `NAME`, falling back to the contents of the file at
/// `NAME_FILE`. The file form is preferred in deployment so the credential
/// arrives as a mounted file rather than an environment variable visible to
/// anything that can read the container's environment.
fn env_or_file(name: &str) -> anyhow::Result<Option<String>> {
  if let Ok(value) = env::var(name) {
    let value = value.trim().to_string();
    if !value.is_empty() {
      return Ok(Some(value));
    }
  }
  let file_var = format!("{name}_FILE");
  if let Ok(path) = env::var(&file_var) {
    let path = path.trim();
    if !path.is_empty() {
      let value = fs::read_to_string(path).with_context(|| {
        format!(
          "{file_var} points at '{path}', which could not be read"
        )
      })?;
      let value = value.trim().to_string();
      if value.is_empty() {
        bail!("{file_var} points at '{path}', which is empty");
      }
      return Ok(Some(value));
    }
  }
  Ok(None)
}

fn require(name: &str) -> anyhow::Result<String> {
  env_or_file(name)?.ok_or_else(|| {
    anyhow!(
      "{name} (or {name}_FILE) must be set when {ENV_ENABLED} is true"
    )
  })
}

fn duration_from_env(
  name: &str,
  default_seconds: u64,
) -> anyhow::Result<Duration> {
  match env::var(name) {
    Err(_) => Ok(Duration::from_secs(default_seconds)),
    Ok(raw) => {
      let raw = raw.trim();
      if raw.is_empty() {
        return Ok(Duration::from_secs(default_seconds));
      }
      let seconds = raw.parse::<u64>().with_context(|| {
        format!(
          "{name} must be a whole number of seconds, got '{raw}'"
        )
      })?;
      Ok(Duration::from_secs(seconds))
    }
  }
}

/// Aliases and environment names appear inside interpolation tokens and are
/// matched against Cadastre's declared `secret_ref` convention
/// (`^(infisical|woodpecker)://[a-z0-9-]+/[a-z0-9-]+/[A-Za-z0-9_]+$`).
/// Enforcing the charset here keeps every token this fork resolves valid
/// against that convention by construction.
fn validate_ref_segment(
  kind: &str,
  value: &str,
) -> anyhow::Result<()> {
  if value.is_empty() {
    bail!("{kind} must not be empty");
  }
  if !value
    .chars()
    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
  {
    bail!(
      "{kind} '{value}' must match [a-z0-9-]+ to satisfy the estate secret_ref convention"
    );
  }
  Ok(())
}

fn parse_projects(
  raw: &str,
) -> anyhow::Result<Vec<(String, String)>> {
  let mut projects = Vec::new();
  for entry in raw.split(',') {
    let entry = entry.trim();
    if entry.is_empty() {
      continue;
    }
    let (alias, project_id) = entry
      .split_once('=')
      .ok_or_else(|| anyhow!("{ENV_PROJECTS} entry '{entry}' must be in the form <alias>=<projectId>"))?;
    let alias = alias.trim().to_string();
    let project_id = project_id.trim().to_string();
    validate_ref_segment("project alias", &alias)?;
    if project_id.is_empty() {
      bail!("{ENV_PROJECTS} entry '{entry}' has an empty projectId");
    }
    if projects
      .iter()
      .any(|(existing, _): &(String, String)| existing == &alias)
    {
      bail!("{ENV_PROJECTS} declares alias '{alias}' more than once");
    }
    projects.push((alias, project_id));
  }
  if projects.is_empty() {
    bail!(
      "{ENV_PROJECTS} must declare at least one <alias>=<projectId> pair"
    );
  }
  Ok(projects)
}

fn parse_environments(raw: &str) -> anyhow::Result<Vec<String>> {
  let mut environments = Vec::new();
  for entry in raw.split(',') {
    let entry = entry.trim().to_string();
    if entry.is_empty() {
      continue;
    }
    validate_ref_segment("environment", &entry)?;
    if !environments.contains(&entry) {
      environments.push(entry);
    }
  }
  if environments.is_empty() {
    bail!(
      "{ENV_ENVIRONMENTS} must declare at least one environment slug"
    );
  }
  Ok(environments)
}

impl InfisicalConfig {
  pub fn from_env() -> anyhow::Result<Self> {
    let url = require(ENV_URL)?.trim_end_matches('/').to_string();
    let client_id = require(ENV_CLIENT_ID)?;
    let client_secret = require(ENV_CLIENT_SECRET)?;

    let projects_raw = require(ENV_PROJECTS)?;
    let projects = parse_projects(&projects_raw)?;

    let environments_raw = env::var(ENV_ENVIRONMENTS)
      .ok()
      .filter(|v| !v.trim().is_empty())
      .unwrap_or_else(|| DEFAULT_ENVIRONMENTS.to_string());
    let environments = parse_environments(&environments_raw)?;

    let scopes = projects
      .into_iter()
      .flat_map(|(alias, project_id)| {
        environments.iter().map(move |environment| Scope {
          alias: alias.clone(),
          project_id: project_id.clone(),
          environment: environment.clone(),
        })
      })
      .collect::<Vec<_>>();

    let secret_path = env::var(ENV_SECRET_PATH)
      .ok()
      .filter(|v| !v.trim().is_empty())
      .unwrap_or_else(|| DEFAULT_SECRET_PATH.to_string());

    let cache_ttl =
      duration_from_env(ENV_CACHE_TTL, DEFAULT_CACHE_TTL_SECONDS)?;
    let stale_max =
      duration_from_env(ENV_STALE_MAX, DEFAULT_STALE_MAX_SECONDS)?;
    let timeout =
      duration_from_env(ENV_TIMEOUT, DEFAULT_TIMEOUT_SECONDS)?;

    if stale_max < cache_ttl {
      bail!(
        "{ENV_STALE_MAX} ({stale_max:?}) must be >= {ENV_CACHE_TTL} ({cache_ttl:?})"
      );
    }

    Ok(Self {
      url,
      client_id,
      client_secret,
      scopes,
      secret_path,
      cache_ttl,
      stale_max,
      timeout,
    })
  }
}
