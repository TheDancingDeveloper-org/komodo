//! Authenticated encryption for the on-disk secret snapshot.
//!
//! # The key, and why it is the Infisical client secret
//!
//! The snapshot is encrypted with AES-256-GCM under a key derived (HKDF-SHA256)
//! from the provider's own Infisical client secret plus a random per-file salt.
//! There is no separate key to generate, mount, rotate or lose.
//!
//! The security property this gives is precise, and worth being precise about.
//! It does **not** defend against an attacker who has already compromised the
//! Komodo Core container — such an attacker holds the client secret and can
//! simply ask Infisical for the same values directly, so no local key material
//! could help. What it does defend is the file *at rest and away from that
//! process*: volume backups, disk images, snapshots of the docker volume, a
//! stray `cp`, or anyone with read access to the host filesystem. Those are the
//! realistic ways a cache file leaks, and against all of them the file is inert.
//!
//! Deriving from the client secret also fails safe on rotation: rotate the
//! credential and the old snapshot simply stops decrypting, so the provider
//! discards it and re-fetches. No stale ciphertext outlives the credential that
//! produced it, and no manual re-keying step is needed.
//!
//! # Primitives
//!
//! `aws-lc-rs` -- already compiled into Komodo Core, which installs it as the
//! rustls crypto provider -- so this adds no new dependency to the build.

use anyhow::{Context, bail};
use aws_lc_rs::{
  aead::{
    AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey,
  },
  hkdf::{HKDF_SHA256, Salt},
  rand,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const SALT_LEN: usize = 32;
const KEY_LEN: usize = 32;

/// Domain separation for the KDF, so this key can never collide with another
/// use of the same client secret.
const HKDF_INFO: &[u8] = b"komodo-infisical-snapshot-v1";

pub const ENVELOPE_VERSION: u32 = 1;

/// What actually lands on disk. Only the ciphertext carries secret material.
#[derive(Serialize, Deserialize)]
pub struct Envelope {
  pub version: u32,
  pub kdf: String,
  pub cipher: String,
  pub salt: String,
  pub nonce: String,
  pub ciphertext: String,
}

/// Bind the header to the ciphertext, so the salt, nonce or algorithm names
/// cannot be swapped without the tag check failing.
fn associated_data(envelope: &Envelope) -> Vec<u8> {
  format!(
    "{}|{}|{}|{}|{}",
    envelope.version,
    envelope.kdf,
    envelope.cipher,
    envelope.salt,
    envelope.nonce
  )
  .into_bytes()
}

fn derive_key(
  client_secret: &str,
  salt: &[u8],
) -> anyhow::Result<[u8; KEY_LEN]> {
  let salt = Salt::new(HKDF_SHA256, salt);
  let prk = salt.extract(client_secret.as_bytes());
  let okm = prk.expand(&[HKDF_INFO], HKDF_SHA256).map_err(|_| {
    anyhow::anyhow!("failed to expand the snapshot encryption key")
  })?;
  let mut key = [0u8; KEY_LEN];
  okm.fill(&mut key).map_err(|_| {
    anyhow::anyhow!("failed to derive the snapshot encryption key")
  })?;
  Ok(key)
}

pub fn seal(
  plaintext: &[u8],
  client_secret: &str,
) -> anyhow::Result<Envelope> {
  let mut salt = [0u8; SALT_LEN];
  rand::fill(&mut salt).map_err(|_| {
    anyhow::anyhow!("failed to generate a snapshot salt")
  })?;
  let mut nonce_bytes = [0u8; NONCE_LEN];
  rand::fill(&mut nonce_bytes).map_err(|_| {
    anyhow::anyhow!("failed to generate a snapshot nonce")
  })?;

  let mut key_bytes = derive_key(client_secret, &salt)?;
  let unbound =
    UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| {
      anyhow::anyhow!("failed to build the snapshot encryption key")
    })?;
  key_bytes.zeroize();
  let key = LessSafeKey::new(unbound);

  let mut envelope = Envelope {
    version: ENVELOPE_VERSION,
    kdf: "hkdf-sha256".to_string(),
    cipher: "aes-256-gcm".to_string(),
    salt: data_encoding::BASE64.encode(&salt),
    nonce: data_encoding::BASE64.encode(&nonce_bytes),
    ciphertext: String::new(),
  };

  let mut in_out = plaintext.to_vec();
  key
    .seal_in_place_append_tag(
      Nonce::assume_unique_for_key(nonce_bytes),
      Aad::from(associated_data(&envelope)),
      &mut in_out,
    )
    .map_err(|_| anyhow::anyhow!("failed to encrypt the snapshot"))?;

  envelope.ciphertext = data_encoding::BASE64.encode(&in_out);
  in_out.zeroize();

  Ok(envelope)
}

pub fn open(
  envelope: &Envelope,
  client_secret: &str,
) -> anyhow::Result<Vec<u8>> {
  if envelope.version != ENVELOPE_VERSION {
    bail!(
      "snapshot envelope version {} is not supported (expected {ENVELOPE_VERSION})",
      envelope.version
    );
  }
  if envelope.kdf != "hkdf-sha256" || envelope.cipher != "aes-256-gcm"
  {
    bail!(
      "snapshot uses unsupported algorithms ({} / {})",
      envelope.kdf,
      envelope.cipher
    );
  }

  let salt = data_encoding::BASE64
    .decode(envelope.salt.as_bytes())
    .context("snapshot salt is not valid base64")?;
  let nonce = data_encoding::BASE64
    .decode(envelope.nonce.as_bytes())
    .context("snapshot nonce is not valid base64")?;
  let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| {
    anyhow::anyhow!("snapshot nonce has the wrong length")
  })?;
  let mut in_out = data_encoding::BASE64
    .decode(envelope.ciphertext.as_bytes())
    .context("snapshot ciphertext is not valid base64")?;

  let mut key_bytes = derive_key(client_secret, &salt)?;
  let unbound =
    UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| {
      anyhow::anyhow!("failed to build the snapshot decryption key")
    })?;
  key_bytes.zeroize();
  let key = LessSafeKey::new(unbound);

  let plaintext = key
    .open_in_place(
      Nonce::assume_unique_for_key(nonce),
      Aad::from(associated_data(envelope)),
      &mut in_out,
    )
    // Most often this means the Infisical client secret was rotated, which is
    // benign: the caller discards the snapshot and re-fetches.
    .map_err(|_| {
      anyhow::anyhow!(
        "could not decrypt the snapshot -- it was written under a different \
         Infisical client secret, or the file has been tampered with"
      )
    })?
    .to_vec();

  in_out.zeroize();
  Ok(plaintext)
}

#[cfg(test)]
mod tests {
  use super::*;

  const SECRET: &str = "st.abc123.def456";

  #[test]
  fn round_trips() {
    let envelope = seal(b"the-plaintext", SECRET).expect("seal");
    let opened = open(&envelope, SECRET).expect("open");
    assert_eq!(opened, b"the-plaintext");
  }

  #[test]
  fn plaintext_does_not_appear_in_the_envelope() {
    // The whole point: nothing readable should survive onto disk.
    let envelope =
      seal(b"hunter2-super-secret", SECRET).expect("seal");
    let encoded = serde_json::to_string(&envelope).unwrap();
    assert!(!encoded.contains("hunter2"));
    assert!(!encoded.contains(SECRET));
  }

  #[test]
  fn a_different_client_secret_cannot_decrypt() {
    // This is what makes credential rotation safe: the old snapshot simply
    // stops opening, so it is discarded rather than trusted.
    let envelope = seal(b"payload", SECRET).expect("seal");
    assert!(open(&envelope, "st.rotated.newvalue").is_err());
  }

  #[test]
  fn tampering_with_the_ciphertext_is_detected() {
    let mut envelope = seal(b"payload", SECRET).expect("seal");
    let mut raw = data_encoding::BASE64
      .decode(envelope.ciphertext.as_bytes())
      .unwrap();
    raw[0] ^= 0xff;
    envelope.ciphertext = data_encoding::BASE64.encode(&raw);
    assert!(open(&envelope, SECRET).is_err());
  }

  #[test]
  fn tampering_with_the_header_is_detected() {
    // The salt is authenticated as associated data, so swapping it must fail
    // rather than silently derive a different key.
    let mut envelope = seal(b"payload", SECRET).expect("seal");
    let mut salt = data_encoding::BASE64
      .decode(envelope.salt.as_bytes())
      .unwrap();
    salt[0] ^= 0xff;
    envelope.salt = data_encoding::BASE64.encode(&salt);
    assert!(open(&envelope, SECRET).is_err());
  }

  #[test]
  fn each_write_uses_a_fresh_salt_and_nonce() {
    let a = seal(b"payload", SECRET).expect("seal");
    let b = seal(b"payload", SECRET).expect("seal");
    assert_ne!(a.salt, b.salt);
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(
      a.ciphertext, b.ciphertext,
      "identical ciphertexts would leak equality"
    );
  }
}
