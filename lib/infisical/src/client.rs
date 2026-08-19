//! Minimal Infisical API client: universal-auth login plus raw secret reads.
//!
//! Response shapes below were verified live against the estate's Infisical
//! instance rather than taken from documentation.

use std::{
  collections::HashMap,
  sync::Arc,
  time::{Duration, Instant},
};

use anyhow::{Context, bail};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::config::{InfisicalConfig, Scope};

/// Refresh the access token this long before it actually expires, so a token
/// that is valid at the moment of the check is not rejected mid-request.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
struct LoginResponse {
  #[serde(rename = "accessToken")]
  access_token: String,
  /// Seconds. Verified live as 2592000 for this identity.
  #[serde(rename = "expiresIn")]
  expires_in: u64,
}

#[derive(Deserialize)]
struct RawSecret {
  #[serde(rename = "secretKey")]
  secret_key: String,
  #[serde(rename = "secretValue")]
  secret_value: Option<String>,
  /// Set when the caller's identity may list the secret but not read its
  /// value. Such entries must be skipped, never surfaced as an empty string.
  #[serde(rename = "secretValueHidden", default)]
  secret_value_hidden: bool,
}

#[derive(Deserialize)]
struct RawImport {
  #[serde(default)]
  secrets: Vec<RawSecret>,
}

#[derive(Deserialize)]
struct RawSecretsResponse {
  #[serde(default)]
  secrets: Vec<RawSecret>,
  #[serde(default)]
  imports: Vec<RawImport>,
}

struct CachedToken {
  token: String,
  expires_at: Instant,
}

pub struct InfisicalClient {
  http: reqwest::Client,
  config: InfisicalConfig,
  token: RwLock<Option<CachedToken>>,
}

impl InfisicalClient {
  pub fn new(config: InfisicalConfig) -> anyhow::Result<Arc<Self>> {
    let http = reqwest::Client::builder()
      .timeout(config.timeout)
      .build()
      .context("failed to build Infisical http client")?;
    Ok(Arc::new(Self {
      http,
      config,
      token: RwLock::new(None),
    }))
  }

  pub fn config(&self) -> &InfisicalConfig {
    &self.config
  }

  async fn cached_token(&self) -> Option<String> {
    let guard = self.token.read().await;
    guard
      .as_ref()
      .filter(|cached| cached.expires_at > Instant::now())
      .map(|cached| cached.token.clone())
  }

  async fn login(&self) -> anyhow::Result<String> {
    let response = self
      .http
      .post(format!(
        "{}/api/v1/auth/universal-auth/login",
        self.config.url
      ))
      .json(&serde_json::json!({
        "clientId": self.config.client_id,
        "clientSecret": self.config.client_secret,
      }))
      .send()
      .await
      .context("failed to reach Infisical universal-auth login")?;

    let status = response.status();
    if !status.is_success() {
      // The body of a failed login can echo request details; report only the
      // status so no credential material can reach a log line.
      bail!(
        "Infisical universal-auth login failed with status {status}"
      );
    }

    let login: LoginResponse = response.json().await.context(
      "failed to parse Infisical universal-auth login response",
    )?;

    let lifetime = Duration::from_secs(login.expires_in)
      .checked_sub(TOKEN_REFRESH_MARGIN)
      .unwrap_or_else(|| Duration::from_secs(login.expires_in));

    let mut guard = self.token.write().await;
    *guard = Some(CachedToken {
      token: login.access_token.clone(),
      expires_at: Instant::now() + lifetime,
    });

    Ok(login.access_token)
  }

  async fn token(&self) -> anyhow::Result<String> {
    match self.cached_token().await {
      Some(token) => Ok(token),
      None => self.login().await,
    }
  }

  async fn fetch_scope_with_token(
    &self,
    scope: &Scope,
    token: &str,
  ) -> anyhow::Result<reqwest::Response> {
    let url = format!(
      "{}/api/v3/secrets/raw?workspaceId={}&environment={}&secretPath={}&include_imports=true&expandSecretReferences=true",
      self.config.url,
      urlencoding::encode(&scope.project_id),
      urlencoding::encode(&scope.environment),
      urlencoding::encode(&self.config.secret_path),
    );
    self
      .http
      .get(url)
      .bearer_auth(token)
      .send()
      .await
      .with_context(|| {
        format!(
          "failed to reach Infisical for scope {}/{}",
          scope.alias, scope.environment
        )
      })
  }

  /// Load every readable secret in one scope, keyed by its interpolation
  /// token (`infisical://<alias>/<environment>/<KEY>`).
  pub async fn fetch_scope(
    &self,
    scope: &Scope,
  ) -> anyhow::Result<HashMap<String, String>> {
    let mut response = self
      .fetch_scope_with_token(scope, &self.token().await?)
      .await?;

    // A cached token can be revoked server-side before its stated expiry.
    // Re-login once on 401 rather than failing the whole refresh.
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
      self.token.write().await.take();
      response = self
        .fetch_scope_with_token(scope, &self.login().await?)
        .await?;
    }

    let status = response.status();
    if !status.is_success() {
      bail!(
        "Infisical returned status {status} for scope {}/{}",
        scope.alias,
        scope.environment
      );
    }

    let body: RawSecretsResponse =
      response.json().await.with_context(|| {
        format!(
          "failed to parse Infisical response for scope {}/{}",
          scope.alias, scope.environment
        )
      })?;

    let mut out = HashMap::new();
    let entries = body.secrets.into_iter().chain(
      body.imports.into_iter().flat_map(|import| import.secrets),
    );

    for entry in entries {
      if entry.secret_value_hidden {
        // Listable but not readable by this identity. Skipping leaves the
        // token unresolved, which the interpolation guard turns into a loud
        // failure — far better than substituting an empty value.
        tracing::warn!(target: crate::LOG_TARGET,
          scope = %format!("{}/{}", scope.alias, scope.environment),
          key = %entry.secret_key,
          "Infisical secret value is hidden from the Komodo identity; skipping"
        );
        continue;
      }
      let Some(value) = entry.secret_value else {
        continue;
      };
      out.insert(
        crate::token_for(
          &scope.alias,
          &scope.environment,
          &entry.secret_key,
        ),
        value,
      );
    }

    Ok(out)
  }
}
