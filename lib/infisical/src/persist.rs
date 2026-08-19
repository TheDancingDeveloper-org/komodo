//! On-disk last-known-good snapshot.
//!
//! # Why this exists
//!
//! Without it, Komodo Core's dependency on Infisical is *hard*: the in-memory
//! cache survives an Infisical outage, but not a Core restart during one. Lose
//! both at once -- a host reboot, or Infisical failing to come back after a
//! restart -- and every deploy that references a secret fails, including the
//! deploys you would use to fix it.
//!
//! Persisting the snapshot turns that hard dependency into a soft one: Core can
//! cold-start and keep deploying with the last values it successfully read.
//!
//! # Security trade-off, stated plainly
//!
//! This writes secret values to disk in plaintext. That is a real, new copy of
//! secret material and the reason persistence is opt-in rather than a default.
//!
//! It is consistent with how Komodo already handles secrets -- secret Variables
//! are stored unencrypted in MongoDB, and interpolated values are written into
//! compose and env files on every Periphery host at deploy time -- so it does
//! not introduce a new *class* of exposure. The file is written 0600 inside a
//! directory created 0700, and belongs on a private volume.

use std::{
  collections::HashMap,
  fs,
  io::Write,
  path::{Path, PathBuf},
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

/// Bumped if the on-disk shape changes. An unrecognised version is discarded
/// rather than guessed at -- a mis-parsed secret file is worse than no file.
const FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
pub struct StoredSnapshot {
  pub version: u32,
  /// Wall-clock seconds since the epoch. Wall clock rather than a monotonic
  /// instant because the whole point is to survive a process restart.
  pub fetched_at_unix: u64,
  /// Recorded for diagnostics: which scopes this snapshot covers.
  #[serde(default)]
  pub scopes: Vec<String>,
  pub secrets: HashMap<String, String>,
}

pub fn now_unix() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0)
}

/// Seconds since the snapshot was taken, saturating at zero if the clock has
/// moved backwards since it was written.
pub fn age_seconds(fetched_at_unix: u64) -> u64 {
  now_unix().saturating_sub(fetched_at_unix)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
  use std::os::unix::fs::PermissionsExt;
  fs::set_permissions(path, fs::Permissions::from_mode(mode))
    .with_context(|| {
      format!("failed to set mode {mode:o} on {}", path.display())
    })
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> anyhow::Result<()> {
  Ok(())
}

/// Write the snapshot atomically, so a crash mid-write cannot leave a
/// truncated file that would later be loaded as if it were complete.
pub fn save(
  path: &Path,
  snapshot: &StoredSnapshot,
) -> anyhow::Result<()> {
  if let Some(parent) = path.parent() {
    if !parent.as_os_str().is_empty() && !parent.exists() {
      fs::create_dir_all(parent).with_context(|| {
        format!("failed to create {}", parent.display())
      })?;
      let _ = set_mode(parent, 0o700);
    }
  }

  let tmp: PathBuf = path.with_extension("tmp");
  let encoded = serde_json::to_vec_pretty(snapshot)
    .context("failed to encode the Infisical snapshot")?;

  {
    let mut file = fs::File::create(&tmp).with_context(|| {
      format!("failed to create {}", tmp.display())
    })?;
    // Restrict before writing, so the secrets are never briefly world-readable.
    set_mode(&tmp, 0o600)?;
    file.write_all(&encoded).with_context(|| {
      format!("failed to write {}", tmp.display())
    })?;
    file.sync_all().with_context(|| {
      format!("failed to flush {}", tmp.display())
    })?;
  }

  fs::rename(&tmp, path).with_context(|| {
    format!(
      "failed to move {} into place at {}",
      tmp.display(),
      path.display()
    )
  })?;
  set_mode(path, 0o600)?;

  Ok(())
}

/// Load a previously saved snapshot.
///
/// A missing file is `Ok(None)` -- the normal first-run case. A corrupt or
/// unrecognised file is an error, so it is reported rather than silently
/// treated as "no secrets", which would look identical to a healthy empty read.
pub fn load(path: &Path) -> anyhow::Result<Option<StoredSnapshot>> {
  if !path.exists() {
    return Ok(None);
  }
  let raw = fs::read(path)
    .with_context(|| format!("failed to read {}", path.display()))?;
  let snapshot: StoredSnapshot = serde_json::from_slice(&raw)
    .with_context(|| format!("failed to parse {}", path.display()))?;
  if snapshot.version != FORMAT_VERSION {
    bail!(
      "{} has format version {}, expected {FORMAT_VERSION}",
      path.display(),
      snapshot.version
    );
  }
  Ok(Some(snapshot))
}

pub fn snapshot_from(
  secrets: &HashMap<String, String>,
  scopes: Vec<String>,
) -> StoredSnapshot {
  StoredSnapshot {
    version: FORMAT_VERSION,
    fetched_at_unix: now_unix(),
    scopes,
    secrets: secrets.clone(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
      "komodo-infisical-test-{name}-{}",
      std::process::id()
    ));
    path.push("snapshot.json");
    path
  }

  #[test]
  fn round_trips_a_snapshot() {
    let path = temp_path("roundtrip");
    let _ = fs::remove_dir_all(path.parent().unwrap());

    let mut secrets = HashMap::new();
    secrets.insert(
      "infisical://apps/prod/A".to_string(),
      "one".to_string(),
    );
    let snapshot =
      snapshot_from(&secrets, vec!["apps/prod".to_string()]);
    save(&path, &snapshot).expect("save");

    let loaded = load(&path).expect("load").expect("present");
    assert_eq!(loaded.secrets, secrets);
    assert_eq!(loaded.scopes, vec!["apps/prod".to_string()]);
    assert_eq!(loaded.version, FORMAT_VERSION);

    let _ = fs::remove_dir_all(path.parent().unwrap());
  }

  #[test]
  fn missing_file_is_not_an_error() {
    let path = temp_path("missing");
    let _ = fs::remove_dir_all(path.parent().unwrap());
    assert!(load(&path).expect("load").is_none());
  }

  #[test]
  fn corrupt_file_is_reported_not_swallowed() {
    // Silently treating a corrupt file as "no secrets" would be
    // indistinguishable from a healthy empty read, and would fail deploys with
    // a misleading message.
    let path = temp_path("corrupt");
    let _ = fs::remove_dir_all(path.parent().unwrap());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"{not json").unwrap();
    assert!(load(&path).is_err());
    let _ = fs::remove_dir_all(path.parent().unwrap());
  }

  #[cfg(unix)]
  #[test]
  fn snapshot_is_not_readable_by_others() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_path("mode");
    let _ = fs::remove_dir_all(path.parent().unwrap());

    let snapshot = snapshot_from(&HashMap::new(), vec![]);
    save(&path, &snapshot).expect("save");

    let mode =
      fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
      mode, 0o600,
      "snapshot must not be group/world readable"
    );

    let _ = fs::remove_dir_all(path.parent().unwrap());
  }

  #[test]
  fn wrong_version_is_rejected() {
    let path = temp_path("version");
    let _ = fs::remove_dir_all(path.parent().unwrap());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
      &path,
      br#"{"version":999,"fetched_at_unix":0,"scopes":[],"secrets":{}}"#,
    )
    .unwrap();
    assert!(load(&path).is_err());
    let _ = fs::remove_dir_all(path.parent().unwrap());
  }
}
