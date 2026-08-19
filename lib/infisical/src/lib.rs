//! Infisical secret provider for Komodo Core.
//!
//! # Why this exists
//!
//! Upstream Komodo has no external secret-manager connector. Secret values are
//! therefore copied by hand into Stack / Deployment environments, where they
//! become point-in-time snapshots that drift silently away from the value in
//! Infisical. This crate closes that gap.
//!
//! # How it hooks in
//!
//! Komodo's interpolator ([`svi`], `Interpolator::DoubleBrackets`) resolves
//! `[[TOKEN]]` by exact-match lookup in a `HashMap<String, String>`. So this
//! provider does not need a new parser, new syntax support, a UI change, or a
//! database migration — it only needs to put extra entries into the map that
//! `get_variables_and_secrets` already returns.
//!
//! Entries are keyed by a token whose shape matches the estate's declared
//! Cadastre `secret_ref` convention:
//!
//! ```text
//! [[infisical://<project-alias>/<environment>/<SECRET_KEY>]]
//! ```
//!
//! Because the entries land in the *secrets* half of the map (not the
//! variables half), Komodo's existing redaction applies unchanged: values are
//! replaced in logs and only the token name is shown.
//!
//! # Failure behaviour
//!
//! `svi` is called with `fail_on_missing_variable = false`, which leaves an
//! unresolved token in the output *verbatim*. Left alone, a failed lookup
//! would deploy the literal string `[[infisical://...]]` as a password. This
//! provider therefore never silently substitutes a blank, and
//! `interpolate` carries a companion guard that turns any surviving
//! `infisical://` token into a hard error.
//!
//! The provider itself is deliberately *not* fatal to its caller:
//! `get_variables_and_secrets` is also used by every alerter, so making a
//! provider outage fail that function would suppress the very alerts telling
//! you Infisical is down. Instead the failure is localised — the provider logs
//! loudly and contributes nothing, and only resources that actually reference
//! an `infisical://` token fail, via the guard.

use std::{
  collections::HashMap,
  sync::{Arc, OnceLock},
};

use tokio::sync::{Mutex, RwLock};

mod client;
mod config;
mod persist;

pub use config::{InfisicalConfig, Scope, enabled};

use client::InfisicalClient;

/// Prefix identifying an Infisical interpolation token.
///
/// Kept in sync by hand with `interpolate::INFISICAL_TOKEN_PREFIX`. The
/// duplication is deliberate: `interpolate` is also compiled into Periphery,
/// and depending on this crate would pull `reqwest` and `tokio` into that
/// binary for the sake of one string constant.
pub const TOKEN_PREFIX: &str = "infisical://";

/// Build the interpolation token for a secret.
pub fn token_for(
  alias: &str,
  environment: &str,
  key: &str,
) -> String {
  format!("{TOKEN_PREFIX}{alias}/{environment}/{key}")
}

struct Snapshot {
  secrets: Arc<HashMap<String, String>>,
  /// Wall-clock, not a monotonic `Instant`, because a snapshot restored from
  /// disk has to carry an age across a process restart.
  fetched_at_unix: u64,
}

struct ProviderState {
  client: Arc<InfisicalClient>,
  cache: RwLock<Option<Snapshot>>,
  /// Held across a refresh so a burst of concurrent deploys triggers one
  /// upstream fetch rather than one per deploy.
  refresh: Mutex<()>,
}

impl ProviderState {
  fn scope_names(&self) -> Vec<String> {
    self
      .client
      .config()
      .scopes
      .iter()
      .map(|scope| format!("{}/{}", scope.alias, scope.environment))
      .collect()
  }

  async fn fresh_snapshot(
    &self,
  ) -> Option<Arc<HashMap<String, String>>> {
    let guard = self.cache.read().await;
    guard
      .as_ref()
      .filter(|snapshot| {
        persist::age_seconds(snapshot.fetched_at_unix)
          < self.client.config().cache_ttl.as_secs()
      })
      .map(|snapshot| snapshot.secrets.clone())
  }

  async fn refresh(
    &self,
  ) -> anyhow::Result<Arc<HashMap<String, String>>> {
    let mut merged: HashMap<String, String> = HashMap::new();
    for scope in &self.client.config().scopes {
      merged.extend(self.client.fetch_scope(scope).await?);
    }

    let secrets = Arc::new(merged);
    let fetched_at_unix = persist::now_unix();

    {
      let mut guard = self.cache.write().await;
      *guard = Some(Snapshot {
        secrets: secrets.clone(),
        fetched_at_unix,
      });
    }

    // Persist the new last-known-good set. Best effort: a failure to write the
    // cache must not fail a refresh that otherwise succeeded, because the
    // in-memory copy is already good and deploys can proceed on it.
    if let Some(path) = &self.client.config().cache_file {
      let snapshot =
        persist::snapshot_from(&secrets, self.scope_names());
      if let Err(error) = persist::save(path, &snapshot) {
        tracing::error!(
          path = %path.display(),
          "Failed to persist the Infisical snapshot; Core will not be able to \
           cold-start with these values if Infisical is unreachable: {error:#}"
        );
      }
    }

    Ok(secrets)
  }

  /// Restore the last-known-good snapshot from disk when nothing is cached in
  /// memory yet -- the cold-start case this whole module exists for.
  async fn seed_from_disk(&self) {
    let Some(path) = &self.client.config().cache_file else {
      return;
    };
    if self.cache.read().await.is_some() {
      return;
    }

    match persist::load(path) {
      Ok(None) => {
        tracing::warn!(
          path = %path.display(),
          "No persisted Infisical snapshot to fall back on"
        );
      }
      Ok(Some(stored)) => {
        let age = persist::age_seconds(stored.fetched_at_unix);
        tracing::warn!(
          path = %path.display(),
          count = stored.secrets.len(),
          age_seconds = age,
          scopes = %stored.scopes.join(", "),
          "Restored the last-known-good Infisical snapshot from disk"
        );
        let mut guard = self.cache.write().await;
        *guard = Some(Snapshot {
          secrets: Arc::new(stored.secrets),
          fetched_at_unix: stored.fetched_at_unix,
        });
      }
      Err(error) => {
        tracing::error!(
          path = %path.display(),
          "Could not read the persisted Infisical snapshot: {error:#}"
        );
      }
    }
  }

  /// Decide what to serve when a refresh has failed.
  async fn serve_stale(
    &self,
    error: anyhow::Error,
  ) -> anyhow::Result<Arc<HashMap<String, String>>> {
    self.seed_from_disk().await;

    let guard = self.cache.read().await;
    let Some(snapshot) = guard.as_ref() else {
      return Err(error.context(
        "no cached or persisted Infisical secrets are available to fall back on",
      ));
    };

    let age = persist::age_seconds(snapshot.fetched_at_unix);
    let config = self.client.config();

    if let Some(max) = config.stale_max {
      if age > max.as_secs() {
        return Err(error.context(format!(
          "the last known Infisical secrets are {age}s old, beyond the configured \
           limit of {}s",
          max.as_secs()
        )));
      }
    }

    // Escalate the log level with age. A brief outage is a warning; a long one
    // means deploys have been running on values nobody has revalidated, which
    // deserves to look like a problem.
    if age >= config.stale_warn.as_secs() {
      tracing::error!(
        age_seconds = age,
        "Infisical has been unreachable for a long time; still deploying with \
         the last known good secrets, which may now be out of date: {error:#}"
      );
    } else {
      tracing::warn!(
        age_seconds = age,
        "Infisical refresh failed; serving the last known good secrets: {error:#}"
      );
    }

    Ok(snapshot.secrets.clone())
  }

  /// Return the current secret map, refreshing if the cache has aged out.
  ///
  /// Falls back to the last known good values -- in memory, or restored from
  /// disk after a restart -- rather than failing, so an Infisical outage does
  /// not stop the estate from deploying. See `InfisicalConfig::stale_max`.
  async fn snapshot(
    &self,
  ) -> anyhow::Result<Arc<HashMap<String, String>>> {
    if let Some(secrets) = self.fresh_snapshot().await {
      return Ok(secrets);
    }

    let _refreshing = self.refresh.lock().await;

    // Another task may have refreshed while this one waited for the lock.
    if let Some(secrets) = self.fresh_snapshot().await {
      return Ok(secrets);
    }

    match self.refresh().await {
      Ok(secrets) => Ok(secrets),
      Err(error) => self.serve_stale(error).await,
    }
  }
}

fn state() -> Result<&'static Arc<ProviderState>, &'static String> {
  static STATE: OnceLock<Result<Arc<ProviderState>, String>> =
    OnceLock::new();
  STATE
    .get_or_init(|| {
      let config =
        InfisicalConfig::from_env().map_err(|e| format!("{e:#}"))?;
      let scopes = config
        .scopes
        .iter()
        .map(|scope| format!("{}/{}", scope.alias, scope.environment))
        .collect::<Vec<_>>()
        .join(", ");
      tracing::info!(
        url = %config.url,
        scopes = %scopes,
        cache_ttl_seconds = config.cache_ttl.as_secs(),
        "Infisical secret provider enabled"
      );
      let client =
        InfisicalClient::new(config).map_err(|e| format!("{e:#}"))?;
      Ok(Arc::new(ProviderState {
        client,
        cache: RwLock::new(None),
        refresh: Mutex::new(()),
      }))
    })
    .as_ref()
}

/// Validate configuration and warm the cache.
///
/// Called once at Core startup so a misconfigured provider is reported at boot
/// with a clear message, rather than surfacing as a confusing deploy failure
/// hours later.
pub async fn preload() -> anyhow::Result<()> {
  if !enabled() {
    return Ok(());
  }
  let state = state().map_err(|e| anyhow::anyhow!("{e}"))?;
  let secrets = state.snapshot().await?;

  // Report whether these values came from Infisical just now or from the
  // persisted fallback, so a cold start during an outage is obvious in the log
  // rather than looking like a normal healthy boot.
  let age = {
    let guard = state.cache.read().await;
    guard
      .as_ref()
      .map(|s| persist::age_seconds(s.fetched_at_unix))
  };
  match age {
    Some(age) if age > state.client.config().cache_ttl.as_secs() => {
      tracing::warn!(
        count = secrets.len(),
        age_seconds = age,
        "Started with the last known good Infisical secrets; a live refresh did \
         not succeed"
      );
    }
    _ => {
      tracing::info!(
        count = secrets.len(),
        "Loaded secrets from Infisical"
      );
    }
  }
  Ok(())
}

/// Merge Infisical secrets into the map Komodo interpolates from.
///
/// Never returns an error: see the module docs on why a provider outage must
/// not fail every caller of `get_variables_and_secrets`.
pub async fn extend_secrets(secrets: &mut HashMap<String, String>) {
  if !enabled() {
    return;
  }

  let state = match state() {
    Ok(state) => state,
    Err(error) => {
      tracing::error!(
        "Infisical secret provider is enabled but misconfigured; \
         no Infisical secrets will be available: {error}"
      );
      return;
    }
  };

  match state.snapshot().await {
    Ok(loaded) => {
      for (token, value) in loaded.iter() {
        secrets.insert(token.clone(), value.clone());
      }
    }
    Err(error) => {
      tracing::error!(
        "Failed to load secrets from Infisical; any resource referencing an \
         '{TOKEN_PREFIX}' token will fail to deploy: {error:#}"
      );
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn token_matches_cadastre_secret_ref_convention() {
    // ^(infisical|woodpecker)://[a-z0-9-]+/[a-z0-9-]+/[A-Za-z0-9_]+$
    assert_eq!(
      token_for("apps", "prod", "HOMELAB_KOMODO_API_KEY"),
      "infisical://apps/prod/HOMELAB_KOMODO_API_KEY"
    );
  }

  #[test]
  fn disabled_provider_is_a_no_op() {
    // With KOMODO_INFISICAL_ENABLED unset, Core must behave exactly as upstream.
    assert!(!enabled());
  }
}
