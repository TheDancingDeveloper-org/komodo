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
  time::Instant,
};

use tokio::sync::{Mutex, RwLock};

mod client;
mod config;

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
  fetched_at: Instant,
}

struct ProviderState {
  client: Arc<InfisicalClient>,
  cache: RwLock<Option<Snapshot>>,
  /// Held across a refresh so a burst of concurrent deploys triggers one
  /// upstream fetch rather than one per deploy.
  refresh: Mutex<()>,
}

impl ProviderState {
  async fn fresh_snapshot(
    &self,
  ) -> Option<Arc<HashMap<String, String>>> {
    let guard = self.cache.read().await;
    guard
      .as_ref()
      .filter(|snapshot| {
        snapshot.fetched_at.elapsed() < self.client.config().cache_ttl
      })
      .map(|snapshot| snapshot.secrets.clone())
  }

  async fn refresh(
    &self,
  ) -> anyhow::Result<Arc<HashMap<String, String>>> {
    let mut merged: HashMap<String, String> = HashMap::new();
    for scope in &self.client.config().scopes {
      let scope_secrets = self.client.fetch_scope(scope).await?;
      merged.extend(scope_secrets);
    }
    let secrets = Arc::new(merged);
    let mut guard = self.cache.write().await;
    *guard = Some(Snapshot {
      secrets: secrets.clone(),
      fetched_at: Instant::now(),
    });
    Ok(secrets)
  }

  /// Return the current secret map, refreshing if the cache has aged out.
  ///
  /// If a refresh fails but a previous snapshot is still within
  /// `stale_max`, that snapshot is served with a warning. Serving a slightly
  /// stale secret beats failing every deploy in the estate the moment
  /// Infisical restarts — and the window is bounded and configurable.
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
      Err(error) => {
        let guard = self.cache.read().await;
        match guard.as_ref() {
          Some(snapshot)
            if snapshot.fetched_at.elapsed()
              < self.client.config().stale_max =>
          {
            tracing::warn!(
              age_seconds = snapshot.fetched_at.elapsed().as_secs(),
              "Infisical refresh failed; serving cached secrets: {error:#}"
            );
            Ok(snapshot.secrets.clone())
          }
          _ => Err(error),
        }
      }
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
  tracing::info!(
    count = secrets.len(),
    "Loaded secrets from Infisical"
  );
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
