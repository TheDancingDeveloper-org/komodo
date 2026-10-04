//! Runtime configuration, read from the environment (and overridable by CLI
//! flags). Credentials are only ever held in memory and sent as request
//! headers to Komodo; no tool returns them.

use anyhow::{Context, bail};

/// Default protected-stack patterns: a stack whose name matches one of these
/// can only be mutated when named exactly in `KOMODO_MCP_ALLOW_PROTECTED`.
pub const DEFAULT_PROTECTED: &str = "*prod*";

#[derive(Clone)]
pub struct Config {
  pub url: String,
  pub key: String,
  pub secret: String,
  pub policy: Policy,
  /// Asserted actor stamped on mutating calls (`X-Komodo-Actor`).
  pub actor: String,
}

impl std::fmt::Debug for Config {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Config")
      .field("url", &self.url)
      .field("key", &"<withheld>")
      .field("secret", &"<withheld>")
      .field("policy", &self.policy)
      .field("actor", &self.actor)
      .finish()
  }
}

/// Which stacks the mutating tools (`write_stack_file`, `deploy_stack`) may
/// touch. Read-only by default.
#[derive(Debug, Clone, Default)]
pub struct Policy {
  /// Stack name patterns (`*` globs) that mutating tools may target.
  pub write: Vec<String>,
  /// Stack name patterns that are protected (default `*prod*`).
  pub protected: Vec<String>,
  /// Exact stack names that are allowed despite matching `protected`.
  pub allow_protected: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
  Allowed,
  /// Not in the write allowlist (the read-only default).
  NotAllowlisted,
  /// Protected (e.g. prod) and not explicitly opted in by exact name.
  Protected,
}

impl Policy {
  pub fn decide(&self, stack_name: &str) -> Decision {
    let protected =
      self.protected.iter().any(|p| glob_match(p, stack_name));
    if protected {
      // Globs never unlock a protected stack: only an exact name does.
      if self.allow_protected.iter().any(|n| n == stack_name) {
        Decision::Allowed
      } else {
        Decision::Protected
      }
    } else if self.write.iter().any(|p| glob_match(p, stack_name)) {
      Decision::Allowed
    } else {
      Decision::NotAllowlisted
    }
  }

  pub fn read_only(&self) -> bool {
    self.write.is_empty() && self.allow_protected.is_empty()
  }
}

/// `*` matches any run of characters; everything else is literal.
pub fn glob_match(pattern: &str, text: &str) -> bool {
  let parts: Vec<&str> = pattern.split('*').collect();
  if parts.len() == 1 {
    return pattern == text;
  }
  let mut rest = text;
  for (i, part) in parts.iter().enumerate() {
    if i == 0 {
      match rest.strip_prefix(part) {
        Some(r) => rest = r,
        None => return false,
      }
    } else if i == parts.len() - 1 {
      return rest.ends_with(part);
    } else {
      match rest.find(part) {
        Some(idx) => rest = &rest[idx + part.len()..],
        None => return false,
      }
    }
  }
  true
}

pub fn split_list(s: &str) -> Vec<String> {
  s.split([',', ' ', '\n'])
    .map(str::trim)
    .filter(|s| !s.is_empty())
    .map(String::from)
    .collect()
}

fn env_first(names: &[&str]) -> Option<String> {
  names.iter().find_map(|n| {
    std::env::var(n).ok().filter(|v| !v.trim().is_empty())
  })
}

/// Header-safe actor/reason text: printable ASCII, bounded length.
pub fn sanitize_header(s: &str) -> String {
  s.chars()
    .filter(|c| c.is_ascii_graphic() || *c == ' ')
    .take(200)
    .collect::<String>()
    .trim()
    .to_string()
}

pub struct Overrides {
  pub write: Option<String>,
  pub protected: Option<String>,
  pub allow_protected: Option<String>,
}

impl Config {
  pub fn from_env(o: Overrides) -> anyhow::Result<Config> {
    let url = env_first(&["KOMODO_URL", "KOMODO_ADDRESS"])
      .context("KOMODO_URL (or KOMODO_ADDRESS) is not set")?;
    let key =
      env_first(&["HOMELAB_KOMODO_API_KEY", "KOMODO_API_KEY"])
        .context(
          "HOMELAB_KOMODO_API_KEY (or KOMODO_API_KEY) is not set",
        )?;
    let secret = env_first(&[
      "HOMELAB_KOMODO_API_SECRET",
      "KOMODO_API_SECRET",
    ])
    .context(
      "HOMELAB_KOMODO_API_SECRET (or KOMODO_API_SECRET) is not set",
    )?;
    let url = url.trim().trim_end_matches('/').to_string();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
      bail!("KOMODO_URL must start with http:// or https://");
    }
    let write = o
      .write
      .or_else(|| env_first(&["KOMODO_MCP_WRITE_STACKS"]))
      .unwrap_or_default();
    let protected = o
      .protected
      .or_else(|| env_first(&["KOMODO_MCP_PROTECTED_STACKS"]))
      .unwrap_or_else(|| DEFAULT_PROTECTED.to_string());
    let allow_protected = o
      .allow_protected
      .or_else(|| env_first(&["KOMODO_MCP_ALLOW_PROTECTED"]))
      .unwrap_or_default();
    let actor = env_first(&["KOMODO_MCP_ACTOR"])
      .or_else(|| {
        env_first(&["VOGT_SESSION_ID", "VOGT_SESSION"])
          .map(|s| format!("vogt-session:{s}"))
      })
      .unwrap_or_else(|| String::from("komodo-mcp"));
    Ok(Config {
      url,
      key,
      secret,
      policy: Policy {
        write: split_list(&write),
        protected: split_list(&protected),
        allow_protected: split_list(&allow_protected),
      },
      actor: sanitize_header(&actor),
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn policy(write: &str, protected: &str, allow: &str) -> Policy {
    Policy {
      write: split_list(write),
      protected: split_list(protected),
      allow_protected: split_list(allow),
    }
  }

  #[test]
  fn read_only_by_default() {
    let p = policy("", DEFAULT_PROTECTED, "");
    assert!(p.read_only());
    assert_eq!(p.decide("vogt-dev"), Decision::NotAllowlisted);
  }

  #[test]
  fn globs_allow_but_never_unlock_prod() {
    let p = policy("*", DEFAULT_PROTECTED, "");
    assert_eq!(p.decide("vogt-dev"), Decision::Allowed);
    assert_eq!(p.decide("vogt-prod"), Decision::Protected);
    let p = policy("vogt-*", DEFAULT_PROTECTED, "");
    assert_eq!(p.decide("vogt-prod"), Decision::Protected);
  }

  #[test]
  fn prod_requires_exact_opt_in() {
    let p = policy("vogt-dev", DEFAULT_PROTECTED, "vogt-prod");
    assert_eq!(p.decide("vogt-prod"), Decision::Allowed);
    assert_eq!(p.decide("other-prod"), Decision::Protected);
    // A glob in the opt-in list is treated literally, not as a pattern.
    let p = policy("", DEFAULT_PROTECTED, "*prod*");
    assert_eq!(p.decide("vogt-prod"), Decision::Protected);
  }

  #[test]
  fn glob_semantics() {
    assert!(glob_match("*prod*", "vogt-prod"));
    assert!(glob_match("vogt-*", "vogt-dev"));
    assert!(!glob_match("vogt-*", "xvogt-dev"));
    assert!(glob_match("a*c", "abc"));
    assert!(!glob_match("a*c", "abd"));
    assert!(glob_match("exact", "exact"));
    assert!(!glob_match("exact", "exactly"));
  }

  #[test]
  fn header_sanitising() {
    assert_eq!(sanitize_header("a\nb\u{7f}c é"), "abc");
  }
}
