//! Proves the property that makes the Infisical dependency soft rather than
//! hard: Komodo Core can cold-start with **no** in-memory cache, fail to reach
//! Infisical entirely, and still resolve secrets from the persisted
//! last-known-good snapshot.
//!
//! Its own test binary because the provider initialises its configuration once
//! per process, so this needs a process where Infisical is unreachable.
//!
//! Needs no network: it points the provider at a closed local port.

use std::{collections::HashMap, fs, path::PathBuf};

fn cache_path() -> PathBuf {
  let mut path = std::env::temp_dir();
  path.push(format!(
    "komodo-infisical-coldstart-{}",
    std::process::id()
  ));
  path.push("snapshot.json");
  path
}

/// A snapshot as `persist::save` would have written it during a healthy
/// refresh, before Infisical went away.
fn write_snapshot(path: &PathBuf) {
  fs::create_dir_all(path.parent().unwrap()).unwrap();
  fs::write(
    path,
    br#"{
      "version": 1,
      "fetched_at_unix": 1,
      "scopes": ["apps/prod"],
      "secrets": {
        "infisical://apps/prod/DB_PASSWORD": "last-known-good",
        "infisical://apps/prod/API_TOKEN": "also-known-good"
      }
    }"#,
  )
  .unwrap();
}

#[tokio::test]
async fn cold_starts_from_disk_when_infisical_is_unreachable() {
  let path = cache_path();
  let _ = fs::remove_dir_all(path.parent().unwrap());
  write_snapshot(&path);

  // SAFETY: single-threaded setup at the very start of this test binary,
  // before any provider state has been initialised.
  unsafe {
    std::env::set_var("KOMODO_INFISICAL_ENABLED", "true");
    // Port 1 is closed, so this fails fast and deterministically -- it stands
    // in for "Infisical is down".
    std::env::set_var("KOMODO_INFISICAL_URL", "http://127.0.0.1:1");
    std::env::set_var("KOMODO_INFISICAL_CLIENT_ID", "unused");
    std::env::set_var("KOMODO_INFISICAL_CLIENT_SECRET", "unused");
    std::env::set_var(
      "KOMODO_INFISICAL_PROJECTS",
      "apps=some-project-id",
    );
    std::env::set_var("KOMODO_INFISICAL_ENVIRONMENTS", "prod");
    std::env::set_var(
      "KOMODO_INFISICAL_CACHE_FILE",
      path.to_str().unwrap(),
    );
    std::env::set_var("KOMODO_INFISICAL_TIMEOUT_SECONDS", "2");
  }

  let mut secrets: HashMap<String, String> = HashMap::new();
  infisical::extend_secrets(&mut secrets).await;

  assert_eq!(
    secrets
      .get("infisical://apps/prod/DB_PASSWORD")
      .map(String::as_str),
    Some("last-known-good"),
    "a cold start with Infisical unreachable must still resolve secrets from \
     the persisted snapshot -- this is what stops an Infisical outage from \
     blocking every deploy in the estate"
  );
  assert_eq!(
    secrets.len(),
    2,
    "the whole snapshot should be restored"
  );

  // And repeated calls keep working rather than degrading.
  let mut again: HashMap<String, String> = HashMap::new();
  infisical::extend_secrets(&mut again).await;
  assert_eq!(again.len(), 2);

  let _ = fs::remove_dir_all(path.parent().unwrap());
}
