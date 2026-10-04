//! `komodo-mcp`: an MCP server for Komodo, built on the fork's typed client.
//!
//! Fork-only (TheDancingDeveloper). See `bin/mcp/README.md`.

mod config;
mod komodo;
mod redact;
mod server;
mod tools;

use std::time::Duration;

#[cfg(test)]
mod mock_tests;

use crate::{
  config::{Config, Overrides},
  komodo::Komodo,
  server::{Server, instructions, serve_stdio},
};

const HELP: &str = "komodo-mcp: MCP server (stdio) for Komodo stacks

USAGE:
  komodo-mcp [--allow-write LIST] [--protected LIST] [--allow-protected LIST]
  komodo-mcp --check        verify config + connectivity, then exit
  komodo-mcp --list-tools   print the tool descriptors, then exit

ENVIRONMENT:
  KOMODO_URL                    Komodo Core base URL (or KOMODO_ADDRESS)
  HOMELAB_KOMODO_API_KEY        API key    (or KOMODO_API_KEY)
  HOMELAB_KOMODO_API_SECRET     API secret (or KOMODO_API_SECRET)
  KOMODO_MCP_WRITE_STACKS       stacks (names, * globs) mutating tools may touch; default none
  KOMODO_MCP_PROTECTED_STACKS   protected patterns; default *prod*
  KOMODO_MCP_ALLOW_PROTECTED    exact protected stack names explicitly opted in
  KOMODO_MCP_ACTOR              actor stamped on mutations (default vogt-session:$VOGT_SESSION_ID or komodo-mcp)
";

fn take(args: &mut Vec<String>, flag: &str) -> Option<String> {
  let i = args.iter().position(|a| a == flag)?;
  args.remove(i);
  (i < args.len()).then(|| args.remove(i))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let mut args: Vec<String> = std::env::args().skip(1).collect();
  if args.iter().any(|a| a == "-h" || a == "--help") {
    print!("{HELP}");
    return Ok(());
  }
  if args.iter().any(|a| a == "--list-tools") {
    println!("{}", serde_json::to_string_pretty(&tools::list())?);
    return Ok(());
  }
  let check = args.iter().any(|a| a == "--check");
  args.retain(|a| a != "--check");
  let overrides = Overrides {
    write: take(&mut args, "--allow-write"),
    protected: take(&mut args, "--protected"),
    allow_protected: take(&mut args, "--allow-protected"),
  };
  if let Some(unknown) = args.first() {
    anyhow::bail!("unknown argument `{unknown}` (see --help)");
  }
  let config = Config::from_env(overrides)?;
  let komodo = Komodo::new(&config);
  if check {
    let version = komodo.version().await?;
    eprintln!(
      "komodo-mcp: connected to Komodo Core {version} at {}",
      config.url
    );
    eprintln!("komodo-mcp: actor {:?}", config.actor);
    eprintln!("komodo-mcp: {}", instructions(&config.policy));
    return Ok(());
  }
  eprintln!(
    "komodo-mcp: serving stdio for {} ({})",
    config.url,
    if config.policy.read_only() {
      "read-only"
    } else {
      "mutations allowlisted"
    }
  );
  serve_stdio(Server {
    komodo,
    policy: config.policy,
    poll: Duration::from_secs(2),
  })
  .await
}
