//! Live integration test against a real Infisical instance.
//!
//! Ignored by default because it needs credentials and network. Run it before
//! deploying a new Core image, to prove the provider can actually authenticate
//! and read -- a unit test cannot catch an API shape change upstream.
//!
//!   KOMODO_INFISICAL_ENABLED=true \
//!   KOMODO_INFISICAL_URL=http://192.168.1.75:8400 \
//!   KOMODO_INFISICAL_CLIENT_ID=... \
//!   KOMODO_INFISICAL_CLIENT_SECRET=... \
//!   KOMODO_INFISICAL_PROJECTS=apps=<projectId> \
//!   cargo test -p infisical --test live -- --ignored --nocapture
//!
//! Asserts on shape and counts only. It never prints a secret value.

use std::collections::HashMap;

#[tokio::test]
#[ignore = "requires live Infisical credentials"]
async fn loads_secrets_from_a_live_instance() {
  assert!(
    infisical::enabled(),
    "set KOMODO_INFISICAL_ENABLED=true to run this test"
  );

  let mut secrets: HashMap<String, String> = HashMap::new();
  infisical::extend_secrets(&mut secrets).await;

  assert!(
    !secrets.is_empty(),
    "provider returned no secrets -- check the URL, credentials and project ids"
  );

  for (token, value) in &secrets {
    assert!(
      token.starts_with(infisical::TOKEN_PREFIX),
      "every key must be a provider token, found: {token}"
    );
    // Four segments: 'infisical:', '', '<alias>/<env>/<KEY>'.
    let rest = &token[infisical::TOKEN_PREFIX.len()..];
    let parts = rest.split('/').collect::<Vec<_>>();
    assert_eq!(
      parts.len(),
      3,
      "token must be <alias>/<environment>/<KEY>, found: {token}"
    );
    assert!(!parts[2].is_empty(), "empty secret key in token: {token}");
    // Values may legitimately be empty strings; only the key shape is asserted.
    let _ = value;
  }

  // Print counts, never values.
  println!("resolved {} secrets", secrets.len());
  let mut scopes: Vec<String> = secrets
    .keys()
    .filter_map(|t| {
      let rest = &t[infisical::TOKEN_PREFIX.len()..];
      let mut parts = rest.split('/');
      Some(format!("{}/{}", parts.next()?, parts.next()?))
    })
    .collect();
  scopes.sort();
  scopes.dedup();
  println!("scopes: {scopes:?}");
}

#[tokio::test]
#[ignore = "requires live Infisical credentials"]
async fn caches_rather_than_refetching() {
  assert!(infisical::enabled(), "set KOMODO_INFISICAL_ENABLED=true");

  let mut first = HashMap::new();
  infisical::extend_secrets(&mut first).await;

  let started = std::time::Instant::now();
  let mut second = HashMap::new();
  infisical::extend_secrets(&mut second).await;
  let cached_call = started.elapsed();

  assert_eq!(first.len(), second.len(), "cached read should be identical");
  assert!(
    cached_call < std::time::Duration::from_millis(200),
    "second call took {cached_call:?}; expected a cache hit"
  );
}
