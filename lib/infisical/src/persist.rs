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
//! # The file is encrypted
//!
//! Secret values are never written to disk in the clear. The snapshot is sealed
//! with AES-256-GCM under a key derived from the provider's own Infisical
//! client secret (see [`crate::crypto`]), so the file on disk is inert on its
//! own -- in a volume backup, a disk image, or a stray copy.
//!
//! Defence in depth on top of that: the file is written 0600 inside a directory
//! created 0700, and written atomically.

use std::{
  collections::HashMap,
  fs,
  io::Write,
  path::{Path, PathBuf},
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto;

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

/// Encrypt and write the snapshot atomically, so a crash mid-write cannot
/// leave a truncated file that would later be loaded as if it were complete.
pub fn save(
  path: &Path,
  snapshot: &StoredSnapshot,
  client_secret: &str,
) -> anyhow::Result<()> {
  if let Some(parent) = path.parent() {
    if !parent.as_os_str().is_empty() && !parent.exists() {
      fs::create_dir_all(parent).with_context(|| {
        format!("failed to create {}", parent.display())
      })?;
      let _ = set_mode(parent, 0o700);
    }
  }

  let mut plaintext = serde_json::to_vec(snapshot)
    .context("failed to encode the Infisical snapshot")?;
  let envelope = crypto::seal(&plaintext, client_secret)
    .context("failed to encrypt the Infisical snapshot")?;
  plaintext.zeroize();

  let encoded = serde_json::to_vec_pretty(&envelope)
    .context("failed to encode the Infisical snapshot envelope")?;

  let tmp: PathBuf = path.with_extension("tmp");
  {
    let mut file = fs::File::create(&tmp).with_context(|| {
      format!("failed to create {}", tmp.display())
    })?;
    // Restrict before writing, so the file is never briefly world-readable.
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

/// Decrypt and load a previously saved snapshot.
///
/// A missing file is `Ok(None)` -- the normal first-run case. Anything else
/// that goes wrong is an error rather than a silent `None`, because "no
/// secrets" and "the secrets could not be read" would otherwise look identical
/// while meaning very different things.
///
/// A snapshot that cannot be decrypted is usually just a rotated Infisical
/// client secret. The caller treats that as "no usable snapshot" and re-fetches.
pub fn load(
  path: &Path,
  client_secret: &str,
) -> anyhow::Result<Option<StoredSnapshot>> {
  if !path.exists() {
    return Ok(None);
  }

  let raw = fs::read(path)
    .with_context(|| format!("failed to read {}", path.display()))?;

  let envelope: crypto::Envelope = serde_json::from_slice(&raw).with_context(|| {
    format!(
      "{} is not a valid encrypted snapshot. If it predates snapshot \
       encryption it holds secrets in the clear and should be deleted, not read",
      path.display()
    )
  })?;

  let mut plaintext = crypto::open(&envelope, client_secret)
    .with_context(|| {
      format!("failed to decrypt {}", path.display())
    })?;

  let snapshot: StoredSnapshot = serde_json::from_slice(&plaintext)
    .with_context(|| {
    format!("failed to parse the snapshot in {}", path.display())
  })?;
  plaintext.zeroize();

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

  const SECRET: &str = "st.client.secret";

  fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
      "komodo-infisical-test-{name}-{}",
      std::process::id()
    ));
    path.push("snapshot.json");
    path
  }

  fn sample() -> (StoredSnapshot, HashMap<String, String>) {
    let mut secrets = HashMap::new();
    secrets.insert(
      "infisical://apps/prod/DB_PASSWORD".to_string(),
      "hunter2-super-secret".to_string(),
    );
    let snapshot =
      snapshot_from(&secrets, vec!["apps/prod".to_string()]);
    (snapshot, secrets)
  }

  #[test]
  fn round_trips_a_snapshot() {
    let path = temp_path("roundtrip");
    let _ = fs::remove_dir_all(path.parent().unwrap());

    let (snapshot, secrets) = sample();
    save(&path, &snapshot, SECRET).expect("save");

    let loaded = load(&path, SECRET).expect("load").expect("present");
    assert_eq!(loaded.secrets, secrets);
    assert_eq!(loaded.scopes, vec!["apps/prod".to_string()]);

    let _ = fs::remove_dir_all(path.parent().unwrap());
  }

  #[test]
  fn no_secret_material_is_readable_on_disk() {
    // The property the encryption exists for.
    let path = temp_path("opaque");
    let _ = fs::remove_dir_all(path.parent().unwrap());

    let (snapshot, _) = sample();
    save(&path, &snapshot, SECRET).expect("save");

    let on_disk = fs::read_to_string(&path).expect("read");
    assert!(
      !on_disk.contains("hunter2"),
      "secret value found on disk"
    );
    assert!(
      !on_disk.contains("DB_PASSWORD"),
      "secret name found on disk"
    );
    assert!(!on_disk.contains(SECRET), "client secret found on disk");

    let _ = fs::remove_dir_all(path.parent().unwrap());
  }

  #[test]
  fn a_rotated_client_secret_cannot_read_the_old_snapshot() {
    let path = temp_path("rotated");
    let _ = fs::remove_dir_all(path.parent().unwrap());

    let (snapshot, _) = sample();
    save(&path, &snapshot, SECRET).expect("save");
    assert!(load(&path, "st.rotated.value").is_err());

    let _ = fs::remove_dir_all(path.parent().unwrap());
  }

  #[test]
  fn missing_file_is_not_an_error() {
    let path = temp_path("missing");
    let _ = fs::remove_dir_all(path.parent().unwrap());
    assert!(load(&path, SECRET).expect("load").is_none());
  }

  #[test]
  fn a_legacy_plaintext_file_is_refused_rather_than_read() {
    // Never silently consume a pre-encryption file: it holds secrets in the
    // clear and should be deleted, not trusted.
    let path = temp_path("legacy");
    let _ = fs::remove_dir_all(path.parent().unwrap());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
      &path,
      br#"{"version":1,"fetched_at_unix":0,"scopes":[],"secrets":{"a":"b"}}"#,
    )
    .unwrap();
    assert!(load(&path, SECRET).is_err());
    let _ = fs::remove_dir_all(path.parent().unwrap());
  }

  #[test]
  fn corrupt_file_is_reported_not_swallowed() {
    let path = temp_path("corrupt");
    let _ = fs::remove_dir_all(path.parent().unwrap());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"{not json").unwrap();
    assert!(load(&path, SECRET).is_err());
    let _ = fs::remove_dir_all(path.parent().unwrap());
  }

  #[cfg(unix)]
  #[test]
  fn snapshot_is_not_readable_by_others() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_path("mode");
    let _ = fs::remove_dir_all(path.parent().unwrap());

    let (snapshot, _) = sample();
    save(&path, &snapshot, SECRET).expect("save");

    let mode =
      fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
      mode, 0o600,
      "snapshot must not be group/world readable"
    );

    let _ = fs::remove_dir_all(path.parent().unwrap());
  }
}
