//! Names-only diffs of Komodo environment and resource config.
//!
//! Fork-only (TheDancingDeveloper). Shared by Komodo Core, which records a
//! names-only diff on the Update of every resource config change, and by the
//! `komodo-mcp` binary, which presents stack history and env diffs to agents.
//!
//! The contract of this crate is that **no function returns or renders a
//! value** from an environment block or from any config field that is not on
//! an explicit allowlist ([`SAFE_VALUE_KEYS`]). Values are represented only by
//! a [`fingerprint`] (a sha256 prefix plus the value length), which is enough
//! to tell "changed" from "unchanged" and to compare two stacks, but is not
//! the value. Config fields this crate does not know are treated as secret
//! (default-deny).
//!
//! Note: a fingerprint of a *weak* value (a short dictionary password) can be
//! confirmed by brute force like any deterministic hash. Fingerprints are for
//! change detection, not a secrecy boundary for weak secrets.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Config keys whose **values** hold `KEY=VALUE` lists. These are diffed by
/// variable name; their values are never rendered.
pub const ENV_KEYS: &[&str] =
  &["environment", "build_args", "secret_args"];

/// Config keys whose values are safe to render verbatim in a diff. Anything
/// not listed here (and not in [`ENV_KEYS`]) is rendered as a fingerprint
/// only. Extending this list is a security decision: only add keys that can
/// never carry a credential.
pub const SAFE_VALUE_KEYS: &[&str] = &[
  "name",
  "description",
  "tags",
  "template",
  "deploy",
  "after",
  "server",
  "server_id",
  "swarm",
  "swarm_id",
  "builder",
  "builder_id",
  "linked_repo",
  "git_provider",
  "git_https",
  "git_account",
  "repo",
  "branch",
  "commit",
  "clone_path",
  "reclone",
  "run_directory",
  "build_path",
  "dockerfile_path",
  "file_paths",
  "env_file_path",
  "additional_env_files",
  "config_files",
  "files_on_host",
  "auto_pull",
  "auto_update",
  "auto_update_all_services",
  "auto_update_skip_services",
  "poll_for_updates",
  "run_build",
  "destroy_before_deploy",
  "skip_secret_interp",
  "send_alerts",
  "webhook_enabled",
  "webhook_force_deploy",
  "ignore_services",
  "project_name",
  "registry_provider",
  "registry_account",
  "image",
  "image_registry_account",
  "network",
  "restart",
  "links",
  "termination_signal",
  "termination_timeout",
  "redeploy_on_build",
  "version",
  "auto_increment_version",
  "image_name",
  "image_tag",
];

/// A short, non-reversible stand-in for a value: `sha256:<12 hex>/<len>`.
/// An empty value is rendered as `empty`.
pub fn fingerprint(value: &str) -> String {
  if value.is_empty() {
    return String::from("empty");
  }
  let digest = Sha256::digest(value.as_bytes());
  let mut hex = String::with_capacity(12);
  for byte in digest.iter().take(6) {
    hex.push_str(&format!("{byte:02x}"));
  }
  format!("sha256:{hex}/{}", value.chars().count())
}

/// The value of an env entry with one layer of matching wrapping quotes
/// removed, so `A="x"` and `A=x` fingerprint the same.
pub fn normalize_value(value: &str) -> &str {
  let v = value.trim();
  for q in ['"', '\''] {
    if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
      return &v[1..v.len() - 1];
    }
  }
  v
}

/// If a value is exactly one Komodo interpolation reference such as
/// `[[infisical://apps/prod/X]]` or `[[MY_SECRET]]`, return it. A reference
/// names where a secret lives; it is not the secret, so it is safe to show.
pub fn reference_of(value: &str) -> Option<&str> {
  let v = normalize_value(value);
  let inner = v.strip_prefix("[[")?.strip_suffix("]]")?;
  if inner.is_empty()
    || inner.contains("[[")
    || inner.contains("]]")
    || inner.starts_with('[')
  {
    return None;
  }
  if inner.chars().all(|c| {
    c.is_ascii_alphanumeric()
      || matches!(c, '_' | '-' | '.' | '/' | ':')
  }) {
    Some(v)
  } else {
    None
  }
}

/// One parsed environment entry. The value is kept in memory (it is needed
/// to fingerprint and to scrub) but this type deliberately does not
/// implement `Serialize`, so it cannot be emitted by accident.
#[derive(Clone)]
pub struct EnvEntry {
  pub name: String,
  pub value: String,
}

impl std::fmt::Debug for EnvEntry {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "EnvEntry({}={})", self.name, fingerprint(&self.value))
  }
}

/// The result of parsing an env block.
#[derive(Debug, Clone, Default)]
pub struct ParsedEnv {
  pub entries: Vec<EnvEntry>,
  /// Lines that could not be parsed as `KEY=VALUE` with a valid key. Only
  /// their count is kept: the content of such a line may be a secret (for
  /// example a stray line of a multi-line private key).
  pub unparsed_lines: usize,
}

impl ParsedEnv {
  /// Name -> value (last assignment wins, matching dotenv semantics).
  pub fn map(&self) -> BTreeMap<&str, &str> {
    self
      .entries
      .iter()
      .map(|e| (e.name.as_str(), e.value.as_str()))
      .collect()
  }

  pub fn names(&self) -> Vec<String> {
    let set: BTreeSet<&str> =
      self.entries.iter().map(|e| e.name.as_str()).collect();
    set.into_iter().map(String::from).collect()
  }
}

fn valid_key(key: &str) -> bool {
  let mut chars = key.chars();
  match chars.next() {
    Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
    _ => return false,
  }
  key.len() <= 256
    && chars.all(|c| {
      c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
    })
}

/// Parse a Komodo environment block. Follows Komodo's own
/// `parse_key_value_list` rules (comments, ` #` end-of-line comments, yaml
/// `- ` prefixes, `=` or `:` as the assignment, wrapping quotes) and
/// additionally tolerates quoted values that span several lines, and lines
/// it cannot parse (which are counted, never kept).
pub fn parse_env(input: &str) -> ParsedEnv {
  let mut out = ParsedEnv::default();
  let mut lines = input.split('\n').peekable();
  while let Some(raw) = lines.next() {
    let line = raw.trim();
    if line.is_empty()
      || line.starts_with('#')
      || line.starts_with("//")
    {
      continue;
    }
    let line = line.trim_start_matches('-').trim();
    let line = line.strip_prefix("export ").unwrap_or(line).trim();
    let Some(idx) = line.find(['=', ':']) else {
      out.unparsed_lines += 1;
      continue;
    };
    let mut key = line[..idx].trim();
    let mut value = line[idx + 1..].trim().to_string();
    // Wrapping quotes around key AND value: "KEY=value"
    if (key.starts_with('"') || key.starts_with('\''))
      && !(key.ends_with('"') || key.ends_with('\''))
    {
      key = key[1..].trim();
      if value.ends_with('"') || value.ends_with('\'') {
        value.pop();
        value = value.trim().to_string();
      }
    }
    // A quoted value that does not close on this line continues until a
    // line that ends with the same quote.
    if let Some(q) =
      value.chars().next().filter(|c| *c == '"' || *c == '\'')
      && (value.len() == 1 || !value.ends_with(q))
    {
      for next in lines.by_ref() {
        value.push('\n');
        value.push_str(next);
        if next.trim_end().ends_with(q) {
          break;
        }
      }
      value = value.trim_end().to_string();
    } else if let Some((v, _)) = value.split_once(" #") {
      value = v.trim().to_string();
    }
    if !valid_key(key) {
      out.unparsed_lines += 1;
      continue;
    }
    out.entries.push(EnvEntry {
      name: key.to_string(),
      value,
    });
  }
  out
}

/// Byte range of one parsed environment entry, using the same rules as
/// [`parse_env`]. `start..end` covers from the key through the end of the
/// entry's last line, and not the line terminator that follows it. `line`
/// is 1-based.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSpan {
  pub name: String,
  pub value: String,
  pub start: usize,
  pub end: usize,
  pub line: usize,
}

/// Locate every entry [`parse_env`] would keep, as a byte range in `input`.
pub fn env_spans(input: &str) -> Vec<EnvSpan> {
  let mut out = Vec::new();
  let bytes = input.as_bytes();
  let mut offset = 0usize;
  let mut line_no = 1usize;
  while offset < bytes.len() {
    let (entry_end, lines, span) = span_at(input, offset, line_no);
    if let Some(span) = span {
      out.push(span);
    }
    let mut cursor = offset;
    let mut seen = 0usize;
    while seen < lines && cursor < bytes.len() {
      match bytes[cursor..]
        .iter()
        .position(|b| *b == b'\n')
        .map(|i| cursor + i)
      {
        Some(n) => {
          cursor = n + 1;
          seen += 1;
          line_no += 1;
        }
        None => {
          cursor = bytes.len();
          break;
        }
      }
    }
    if cursor <= offset {
      break;
    }
    offset = cursor;
    let _ = entry_end;
  }
  out
}

/// One entry starting at `offset`: how many source lines it occupies and,
/// when it parses, its span.
fn span_at(
  input: &str,
  offset: usize,
  line_no: usize,
) -> (usize, usize, Option<EnvSpan>) {
  let bytes = input.as_bytes();
  let nl = bytes[offset..]
    .iter()
    .position(|b| *b == b'\n')
    .map(|i| offset + i);
  let line_end = nl.unwrap_or(bytes.len());
  let raw = &input[offset..line_end];
  let trimmed = raw.trim();
  if trimmed.is_empty()
    || trimmed.starts_with('#')
    || trimmed.starts_with("//")
  {
    return (line_end, 1, None);
  }
  let body = trimmed.trim_start_matches('-').trim();
  let body = body.strip_prefix("export ").unwrap_or(body).trim();
  let Some(idx) = body.find(['=', ':']) else {
    return (line_end, 1, None);
  };
  let mut key = body[..idx].trim();
  let mut value = body[idx + 1..].trim().to_string();
  if (key.starts_with('"') || key.starts_with('\''))
    && !(key.ends_with('"') || key.ends_with('\''))
  {
    key = key[1..].trim();
    if value.ends_with('"') || value.ends_with('\'') {
      value.pop();
      value = value.trim().to_string();
    }
  }
  let mut end = line_end;
  let mut lines = 1usize;
  if let Some(q) =
    value.chars().next().filter(|c| *c == '"' || *c == '\'')
    && (value.len() == 1 || !value.ends_with(q))
  {
    let mut cursor = line_end;
    loop {
      if cursor >= bytes.len() || bytes[cursor] != b'\n' {
        end = bytes.len();
        break;
      }
      let next_start = cursor + 1;
      let next_nl = bytes[next_start..]
        .iter()
        .position(|b| *b == b'\n')
        .map(|i| next_start + i);
      let next_end = next_nl.unwrap_or(bytes.len());
      let next = &input[next_start..next_end];
      value.push('\n');
      value.push_str(next);
      end = next_end;
      lines += 1;
      cursor = next_end;
      if next.trim_end().ends_with(q) || next_nl.is_none() {
        break;
      }
    }
    value = value.trim_end().to_string();
  } else if let Some((v, _)) = value.split_once(" #") {
    value = v.trim().to_string();
  }
  if !valid_key(key) {
    return (end, lines, None);
  }
  let lead = raw.len() - raw.trim_start().len();
  let trimmed_start = offset + lead;
  let rel = input[trimmed_start..end]
    .find(key)
    .expect("parsed key sits inside its span");
  (
    end,
    lines,
    Some(EnvSpan {
      name: key.to_string(),
      value,
      start: trimmed_start + rel,
      end,
      line: line_no,
    }),
  )
}

/// What is known about one env value without showing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueRef {
  pub fingerprint: String,
  /// Set when the whole value is one interpolation reference, e.g.
  /// `[[infisical://apps/prod/X]]`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub reference: Option<String>,
}

impl ValueRef {
  pub fn of(value: &str) -> ValueRef {
    ValueRef {
      fingerprint: fingerprint(normalize_value(value)),
      reference: reference_of(value).map(String::from),
    }
  }

  fn render(&self) -> String {
    match &self.reference {
      Some(r) => format!("{r} ({})", self.fingerprint),
      None => self.fingerprint.clone(),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvChange {
  pub name: String,
  pub before: ValueRef,
  pub after: ValueRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedValue {
  pub name: String,
  pub value: ValueRef,
}

/// Names-only diff of two env blocks.
#[derive(
  Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct EnvDiff {
  pub added: Vec<NamedValue>,
  pub removed: Vec<NamedValue>,
  pub changed: Vec<EnvChange>,
  pub unchanged: usize,
  /// Lines on either side that could not be parsed (content withheld).
  #[serde(skip_serializing_if = "is_zero")]
  pub unparsed_lines: usize,
}

fn is_zero(n: &usize) -> bool {
  *n == 0
}

impl EnvDiff {
  pub fn is_empty(&self) -> bool {
    self.added.is_empty()
      && self.removed.is_empty()
      && self.changed.is_empty()
  }
}

/// Diff two env blocks by name. Values are compared after quote
/// normalisation and rendered only as [`ValueRef`]s.
pub fn diff_env(before: &str, after: &str) -> EnvDiff {
  let a = parse_env(before);
  let b = parse_env(after);
  let mut diff = diff_env_maps(&a.map(), &b.map());
  diff.unparsed_lines = a.unparsed_lines + b.unparsed_lines;
  diff
}

/// Diff two name->value maps.
pub fn diff_env_maps(
  a: &BTreeMap<&str, &str>,
  b: &BTreeMap<&str, &str>,
) -> EnvDiff {
  let mut diff = EnvDiff::default();
  for (name, va) in a {
    match b.get(name) {
      None => diff.removed.push(NamedValue {
        name: name.to_string(),
        value: ValueRef::of(va),
      }),
      Some(vb) if normalize_value(va) != normalize_value(vb) => {
        diff.changed.push(EnvChange {
          name: name.to_string(),
          before: ValueRef::of(va),
          after: ValueRef::of(vb),
        })
      }
      Some(_) => diff.unchanged += 1,
    }
  }
  for (name, vb) in b {
    if !a.contains_key(name) {
      diff.added.push(NamedValue {
        name: name.to_string(),
        value: ValueRef::of(vb),
      });
    }
  }
  diff
}

/// One changed non-env config field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldChange {
  /// Dotted path, e.g. `config.branch`.
  pub path: String,
  /// The previous value: verbatim for [`SAFE_VALUE_KEYS`], otherwise a
  /// fingerprint. `None` = not set (default).
  pub before: Option<String>,
  pub after: Option<String>,
}

/// Names-only diff of a resource's config, computed from Komodo's TOML
/// exports (`Update.prev_toml` / `Update.current_toml`).
#[derive(
  Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct ConfigDiff {
  pub fields: Vec<FieldChange>,
  /// Env-like fields (see [`ENV_KEYS`]) keyed by dotted path.
  pub env: BTreeMap<String, EnvDiff>,
}

impl ConfigDiff {
  pub fn is_empty(&self) -> bool {
    self.fields.is_empty() && self.env.values().all(EnvDiff::is_empty)
  }

  /// Human-readable rendering for an Update log. Contains no values except
  /// for allowlisted fields.
  pub fn render(&self) -> String {
    let mut out = String::from(
      "Names-only diff. Env values and non-allowlisted fields are shown as \
       fingerprints (sha256 prefix/length), never as values.\n",
    );
    if self.is_empty() {
      out.push_str("(no config change detected)\n");
      return out;
    }
    for f in &self.fields {
      let show = |v: &Option<String>| {
        v.clone().unwrap_or_else(|| "(unset)".into())
      };
      out.push_str(&format!(
        "~ {}: {} -> {}\n",
        f.path,
        show(&f.before),
        show(&f.after)
      ));
    }
    for (path, d) in &self.env {
      if d.is_empty() {
        continue;
      }
      out.push_str(&format!("{path} ({} unchanged):\n", d.unchanged));
      for a in &d.added {
        out.push_str(&format!(
          "  + {} = {}\n",
          a.name,
          a.value.render()
        ));
      }
      for r in &d.removed {
        out.push_str(&format!(
          "  - {} (was {})\n",
          r.name,
          r.value.render()
        ));
      }
      for c in &d.changed {
        out.push_str(&format!(
          "  ~ {}: {} -> {}\n",
          c.name,
          c.before.render(),
          c.after.render()
        ));
      }
      if d.unparsed_lines > 0 {
        out.push_str(&format!(
          "  ({} unparseable line(s), content withheld)\n",
          d.unparsed_lines
        ));
      }
    }
    out
  }
}

fn render_toml_value(key: &str, value: &toml::Value) -> String {
  if SAFE_VALUE_KEYS.contains(&key) {
    let s = match value {
      toml::Value::String(s) => format!("{s:?}"),
      other => other.to_string(),
    };
    if s.chars().count() > 300 {
      let cut: String = s.chars().take(300).collect();
      format!("{cut}… ({})", fingerprint(&s))
    } else {
      s
    }
  } else {
    let s = match value {
      toml::Value::String(s) => s.clone(),
      other => other.to_string(),
    };
    fingerprint(&s)
  }
}

fn as_env_text(value: Option<&toml::Value>) -> String {
  match value {
    None => String::new(),
    Some(toml::Value::String(s)) => s.clone(),
    // Komodo also accepts `[{variable, value}]` lists.
    Some(toml::Value::Array(items)) => items
      .iter()
      .filter_map(|i| {
        let t = i.as_table()?;
        let k = t.get("variable")?.as_str()?;
        let v = t.get("value")?.as_str()?;
        Some(format!("{k}={v}"))
      })
      .collect::<Vec<_>>()
      .join("\n"),
    Some(other) => other.to_string(),
  }
}

fn diff_tables(
  prefix: &str,
  a: &toml::Table,
  b: &toml::Table,
  out: &mut ConfigDiff,
) {
  let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
  for key in keys {
    let path = if prefix.is_empty() {
      key.clone()
    } else {
      format!("{prefix}.{key}")
    };
    let (va, vb) = (a.get(key), b.get(key));
    if ENV_KEYS.contains(&key.as_str()) {
      let d = diff_env(&as_env_text(va), &as_env_text(vb));
      if !d.is_empty() {
        out.env.insert(path, d);
      }
      continue;
    }
    match (va, vb) {
      (
        Some(toml::Value::Table(ta)),
        Some(toml::Value::Table(tb)),
      ) => diff_tables(&path, ta, tb, out),
      (Some(toml::Value::Table(ta)), None) => {
        diff_tables(&path, ta, &toml::Table::new(), out)
      }
      (None, Some(toml::Value::Table(tb))) => {
        diff_tables(&path, &toml::Table::new(), tb, out)
      }
      (Some(x), Some(y)) if x == y => {}
      (None, None) => {}
      (x, y) => out.fields.push(FieldChange {
        path,
        before: x.map(|v| render_toml_value(key, v)),
        after: y.map(|v| render_toml_value(key, v)),
      }),
    }
  }
}

/// The raw `environment = …` assignment inside a resource export, or `None`
/// when the key is absent. Core's toml_pretty 2.0.0 writes a multiline env as
/// a basic multiline string with no escaping, so a backslash or three quotes
/// in the env makes the export invalid TOML. This is the source text Core
/// stored. The lost-update check compares it, not a parsed value.
pub fn environment_assignment(toml_str: &str) -> Option<String> {
  let rest = toml_str.strip_prefix("environment").or_else(|| {
    let key = toml_str.find("\nenvironment")?;
    toml_str[key + 1..].strip_prefix("environment")
  })?;
  let after = rest.trim_start();
  let after = after.strip_prefix('=')?.trim_start();
  let (_decoded, n) = raw_toml_string(after)?;
  Some(after[..n].to_string())
}

/// Decode one TOML string literal at the start of `s`. Returns the decoded
/// text and how many source bytes the literal occupies, quotes included.
/// Multiline forms are taken verbatim: that is how toml_pretty 2.0.0 writes
/// them, with no escape processing.
fn raw_toml_string(s: &str) -> Option<(String, usize)> {
  if let Some(body) = s.strip_prefix("\"\"\"") {
    let end = body.find("\"\"\"")?;
    return Some((body[..end].to_string(), 3 + end + 3));
  }
  if let Some(body) = s.strip_prefix("'''") {
    let end = body.find("'''")?;
    return Some((body[..end].to_string(), 3 + end + 3));
  }
  let quote = s.chars().next()?;
  if quote != '"' && quote != '\'' {
    return None;
  }
  let mut out = String::new();
  let mut chars = s[quote.len_utf8()..].char_indices();
  while let Some((i, c)) = chars.next() {
    if c == '\\' {
      let (_, n) = chars.next()?;
      out.push(match n {
        'n' => '\n',
        't' => '\t',
        'r' => '\r',
        '\\' => '\\',
        '"' => '"',
        '\'' => '\'',
        other => other,
      });
      continue;
    }
    if c == quote {
      return Some((out, quote.len_utf8() + i + c.len_utf8()));
    }
    if c == '\n' {
      return None;
    }
    out.push(c);
  }
  None
}

/// Extract the single resource table from a Komodo resource TOML export
/// (`[[stack]] ... [stack.config] ...`).
///
/// When the export does not parse — Core's unescaped multiline env — the env
/// assignment is lifted out and the remainder is parsed, so a names-only diff
/// still names the changed keys. The lifted text is not returned.
fn resource_table(toml_str: &str) -> Result<toml::Table, String> {
  if let Ok(table) = resource_table_parsed(toml_str) {
    return Ok(table);
  }
  let assign = environment_assignment(toml_str)
    .ok_or_else(|| String::from("resource TOML did not parse"))?;
  let key_at = toml_str
    .find("\nenvironment")
    .ok_or_else(|| String::from("resource TOML did not parse"))?
    + 1;
  let eq = toml_str[key_at..]
    .find('=')
    .ok_or_else(|| String::from("resource TOML did not parse"))?;
  let value_at = key_at
    + eq
    + 1
    + toml_str[key_at + eq + 1..]
      .find(|c: char| !c.is_whitespace())
      .unwrap_or(0);
  let mut stripped = String::new();
  stripped.push_str(&toml_str[..value_at]);
  stripped.push_str("\"\"");
  stripped.push_str(&toml_str[value_at + assign.len()..]);
  let mut table = resource_table_parsed(&stripped)?;
  if let Some(toml::Value::Table(config)) = table.get_mut("config")
    && let Some((decoded, _)) = raw_toml_string(&assign)
  {
    config.insert("environment".into(), toml::Value::String(decoded));
  }
  Ok(table)
}

fn resource_table_parsed(
  toml_str: &str,
) -> Result<toml::Table, String> {
  if toml_str.trim().is_empty() {
    return Ok(toml::Table::new());
  }
  let doc: toml::Table = toml_str
    .parse()
    // Never echo the parser error: it can quote the offending line.
    .map_err(|_| String::from("resource TOML did not parse"))?;
  for (_, v) in doc {
    if let toml::Value::Array(arr) = v
      && let Some(toml::Value::Table(t)) = arr.into_iter().next()
    {
      return Ok(t);
    }
  }
  Ok(toml::Table::new())
}

/// Names-only diff between two Komodo resource TOML exports.
pub fn diff_resource_toml(
  prev: &str,
  curr: &str,
) -> Result<ConfigDiff, String> {
  let a = resource_table(prev)?;
  let b = resource_table(curr)?;
  let mut out = ConfigDiff::default();
  diff_tables("", &a, &b, &mut out);
  Ok(out)
}

/// Extract the env block (`config.environment`) from a resource TOML export.
pub fn environment_from_toml(
  toml_str: &str,
) -> Result<String, String> {
  let t = resource_table(toml_str)?;
  Ok(as_env_text(
    t.get("config")
      .and_then(|c| c.as_table())
      .and_then(|c| c.get("environment")),
  ))
}

/// Line-level summary of a file change, without content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChange {
  pub before: Option<String>,
  pub after: String,
  pub lines_added: usize,
  pub lines_removed: usize,
}

/// Summarise a file rewrite as fingerprints and multiset line counts.
pub fn diff_file(before: Option<&str>, after: &str) -> FileChange {
  let mut counts: BTreeMap<&str, isize> = BTreeMap::new();
  for l in before.unwrap_or_default().lines() {
    *counts.entry(l).or_default() -= 1;
  }
  for l in after.lines() {
    *counts.entry(l).or_default() += 1;
  }
  let (mut added, mut removed) = (0, 0);
  for c in counts.values() {
    if *c > 0 {
      added += *c as usize;
    } else {
      removed += c.unsigned_abs();
    }
  }
  FileChange {
    before: before.map(fingerprint),
    after: fingerprint(after),
    lines_added: added,
    lines_removed: removed,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const S1: &str = "hunter2-very-secret-value-1";
  const S2: &str = "ghp_FAKEFAKEFAKEFAKEFAKE0123456789";
  const S3: &str = "AAAAprivatekeybodyFAKE";

  fn assert_no_secret(s: &str) {
    for secret in [S1, S2, S3, "hunter2"] {
      assert!(!s.contains(secret), "leaked {secret} in: {s}");
    }
  }

  #[test]
  fn parses_komodo_forms() {
    let env = parse_env(
      "# c\nA=1\nB = two # eol\n- C: 'three'\n\"D=four\"\nexport E=5\n\nnot a line\n",
    );
    let names: Vec<_> =
      env.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["A", "B", "C", "D", "E"]);
    assert_eq!(env.map()["B"], "two");
    assert_eq!(normalize_value(env.map()["C"]), "three");
    assert_eq!(env.unparsed_lines, 1);
  }

  #[test]
  fn multiline_quoted_value_is_one_entry() {
    let env = parse_env(&format!(
      "KEY=\"-----BEGIN PRIVATE KEY-----\n{S3}\n-----END PRIVATE KEY-----\"\nNEXT=1"
    ));
    assert_eq!(env.names(), ["KEY", "NEXT"]);
    assert_eq!(env.unparsed_lines, 0);
  }

  #[test]
  fn invalid_key_is_not_named() {
    // A key that is not an identifier may be secret material.
    let env = parse_env(&format!("{S2} abc:def\n"));
    assert!(env.entries.is_empty());
    assert_eq!(env.unparsed_lines, 1);
  }

  #[test]
  fn env_diff_is_names_only() {
    let before = format!("KEEP=x\nGONE={S1}\nROT={S1}\nREF={S2}");
    let after = format!(
      "KEEP=x\nNEW={S2}\nROT={S2}\nREF=[[infisical://apps/prod/HOMELAB_REF]]"
    );
    let d = diff_env(&before, &after);
    assert_eq!(d.added.len(), 1);
    assert_eq!(d.added[0].name, "NEW");
    assert_eq!(d.removed[0].name, "GONE");
    assert_eq!(d.changed.len(), 2);
    assert_eq!(d.unchanged, 1);
    let r = d.changed.iter().find(|c| c.name == "REF").unwrap();
    assert_eq!(
      r.after.reference.as_deref(),
      Some("[[infisical://apps/prod/HOMELAB_REF]]")
    );
    let json = serde_json::to_string(&d).unwrap();
    assert_no_secret(&json);
    let mut cd = ConfigDiff::default();
    cd.env.insert("config.environment".into(), d);
    assert_no_secret(&cd.render());
  }

  #[test]
  fn quote_style_is_not_a_change() {
    assert!(diff_env("A=\"x\"", "A=x").is_empty());
  }

  #[test]
  fn fingerprint_shape() {
    let f = fingerprint(S1);
    assert!(f.starts_with("sha256:"));
    assert!(f.ends_with(&format!("/{}", S1.len())));
    assert_eq!(fingerprint(""), "empty");
  }

  #[test]
  fn reference_detection() {
    assert!(reference_of("[[infisical://apps/prod/X]]").is_some());
    assert!(reference_of("\"[[MY_SECRET]]\"").is_some());
    assert!(reference_of("pre[[X]]").is_none());
    assert!(reference_of("[[[X]]]").is_none());
    assert!(reference_of("[[has space]]").is_none());
  }

  #[test]
  fn toml_diff_redacts_unknown_and_env() {
    let prev = format!(
      r#"[[stack]]
name = "vogt-dev"

[stack.config]
server = "node-b"
branch = "main"
webhook_secret = "{S1}"
environment = """
A=1
TOKEN={S2}
"""
"#
    );
    let curr = format!(
      r#"[[stack]]
name = "vogt-dev"

[stack.config]
server = "node-b"
branch = "dev"
webhook_secret = "{S3}"
pre_deploy.command = "curl -H 'auth: {S1}'"
environment = """
A=1
TOKEN={S3}
NEW_ONE=[[infisical://apps/prod/NEW_ONE]]
"""
"#
    );
    let d = diff_resource_toml(&prev, &curr).unwrap();
    let paths: Vec<_> =
      d.fields.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
      paths,
      [
        "config.branch",
        "config.pre_deploy.command",
        "config.webhook_secret"
      ]
    );
    let branch = &d.fields[0];
    assert_eq!(branch.before.as_deref(), Some("\"main\""));
    assert_eq!(branch.after.as_deref(), Some("\"dev\""));
    let env = &d.env["config.environment"];
    assert_eq!(env.added[0].name, "NEW_ONE");
    assert_eq!(env.changed[0].name, "TOKEN");
    assert_no_secret(&serde_json::to_string(&d).unwrap());
    assert_no_secret(&d.render());
  }

  #[test]
  fn bad_toml_error_does_not_quote_input() {
    let err =
      diff_resource_toml(&format!("x = {S1}"), "").unwrap_err();
    assert_no_secret(&err);
  }

  #[test]
  fn unescaped_multiline_env_still_names_keys() {
    // toml_pretty 2.0.0 writes this with no escapes, so the export is not
    // valid TOML. The names-only diff must still name the edited key and
    // must not keep the value.
    let prev = "[[stack]]\nname = \"s\"\n\n[stack.config]\nbranch = \"main\"\nenvironment = \"\"\"\nRE=a\\.b\nKEEP=1\n\"\"\"\n";
    let curr = "[[stack]]\nname = \"s\"\n\n[stack.config]\nbranch = \"main\"\nenvironment = \"\"\"\nRE=a\\.b\nKEEP=2\n\"\"\"\n";
    let d = diff_resource_toml(prev, curr).unwrap();
    let env = &d.env["config.environment"];
    assert_eq!(env.changed[0].name, "KEEP");
    let rendered = d.render();
    assert!(!rendered.contains("a\\.b"), "{rendered}");
    assert_eq!(
      environment_assignment(prev),
      Some("\"\"\"\nRE=a\\.b\nKEEP=1\n\"\"\"".into())
    );
  }

  #[test]
  fn environment_extraction() {
    let t = format!(
      "[[stack]]\nname=\"s\"\n[stack.config]\nenvironment = \"\"\"\nK={S1}\n\"\"\"\n"
    );
    let env = environment_from_toml(&t).unwrap();
    assert_eq!(parse_env(&env).names(), ["K"]);
  }

  #[test]
  fn env_spans_match_parse_env() {
    let fixtures = [
      "A=1\nB=2\n",
      "# c\nexport FOO=bar\n- BAZ=qux # note\n",
      "Q=\"line1\nline2\"\nAFTER=1\n",
      "not a pair\n:bad=1\nOK=x\n",
      "A=\"x\"\nB='y'\n",
      "EMPTY=\n",
      "WEIRD:colon\n",
      "  spaced = value  \n",
      "\"KEY=value\"\n",
      "",
      "A=1",
      "MULTI=\"a\nb\nc\"\nZ=9\n",
    ];
    for (i, fixture) in fixtures.iter().enumerate() {
      let parsed = parse_env(fixture);
      let spans = env_spans(fixture);
      assert_eq!(
        spans.len(),
        parsed.entries.len(),
        "fixture {i} count"
      );
      for (span, entry) in spans.iter().zip(&parsed.entries) {
        assert_eq!(span.name, entry.name, "fixture {i}");
        assert_eq!(span.value, entry.value, "fixture {i}");
        assert!(span.start <= span.end);
        assert!(span.end <= fixture.len());
      }
    }
  }

  #[test]
  fn file_change_counts() {
    let c = diff_file(Some("a\nb\nc\n"), "a\nB\nc\nd\n");
    assert_eq!((c.lines_added, c.lines_removed), (2, 1));
    assert!(c.before.is_some());
  }
}
