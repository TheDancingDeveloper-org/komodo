# komodo-mcp

An MCP server (stdio) for Komodo stacks. It is fork-only (TheDancingDeveloper) and built on the fork's typed client (`client/core/rs`). Agents use it in place of raw `curl` against the Komodo API.

- **Typed requests.** Every body is built from Komodo's own request types, so mistakes like `params.id` vs `params.stack`, the envelope shape or a misspelt method name can't happen.
- **Redaction on the server side, default-deny.** `GetStack` returns the whole `.env` inline as `.config.environment`. This server never returns it: env is shown as names, fingerprints and `[[references]]` only. File contents and `deployed_config` are fingerprinted. Any field not classified in `src/redact.rs` is withheld. A test fails when a Komodo rebase adds an unclassified field.
- **Scrubbing as a second layer.** Before any tool result leaves the process, every env value of every stack the call touched is replaced with `[redacted:NAME]`, along with common token shapes. This includes values inside deploy logs, container logs, health-check output and error text.
- **Read-only by default.** `write_stack_file` and `deploy_stack` work only on allowlisted stacks. A protected stack (default pattern `*prod*`) needs its exact name opted in, and a glob never unlocks one. The allowlist is checked against the resolved stack *name*, so passing an id cannot bypass it.
- **Attribution.** Mutating calls send `X-Komodo-Actor`/`X-Komodo-Reason`. The fork's Core records them on the Update (see `bin/core/src/tdd`).

## Tools

| Tool | Kind | What it does |
|---|---|---|
| `stack_lookup(query)` | read | Finds stacks by id or name (exact match first, then substring). For each one it returns server, state, repo/branch, deployed vs latest hash, services, and whether this server may mutate it. |
| `get_stack(stack)` | read | Returns the redacted config and info. |
| `env_diff(stack, against)` | read | Names-only env diff. `against` is one of `{stack}`, `{env_file}`, `{hashes}`, `{update}` or `{last_successful_deploy: true}`. |
| `read_stack_file(stack, path, refresh=true)` | read | Returns a compose/config file from Komodo's cache, refreshing the cache first. Known env values are scrubbed. `.env` files are refused. |
| `write_stack_file(stack, path, content, reason?, dry_run?)` | **mutating** | Runs `RefreshStackCache` first and skips identical content. Then it writes and re-reads to verify. It refuses `.env` files. |
| `deploy_stack(stack, services?, reason?, timeout_secs=900)` | **mutating** | Runs `DeployStack` and polls the Update until it completes. Returns pass/fail and the stages. On failure it adds the failing log tail (HTML stripped, scrubbed); on success it adds container health. |
| `container_health(stack)` | read | Per-service state and docker health. It never returns the inspect dump (env, labels). |
| `container_logs(stack, service, tail=100)` | read | Tails one service's log, scrubbed. Maximum 1000 lines. |
| `stack_history(stack, limit=15, since_last_successful_deploy?)` | read | Shows who changed what: user plus asserted actor, names-only config/env diffs, file-write fingerprints, and deploy results. |

A fingerprint is `sha256:<first 12 hex>/<length>` of the value with its wrapping quotes stripped. It is good for change detection and comparison. It is not a secrecy boundary for *weak* values, which can be brute-forced like any deterministic hash.

## Configuration (environment)

| Variable | Meaning |
|---|---|
| `KOMODO_URL` (or `KOMODO_ADDRESS`) | Komodo Core base URL, e.g. `http://100.92.54.45:3011` |
| `HOMELAB_KOMODO_API_KEY` / `HOMELAB_KOMODO_API_SECRET` | API credentials. `KOMODO_API_KEY`/`KOMODO_API_SECRET` also work. They are only sent to Komodo and never returned by a tool. |
| `KOMODO_MCP_WRITE_STACKS` | Stacks the mutating tools may touch, as names or `*` globs, comma-separated. Default: none, which means read-only. |
| `KOMODO_MCP_PROTECTED_STACKS` | Protected patterns. Default: `*prod*`. |
| `KOMODO_MCP_ALLOW_PROTECTED` | Exact protected stack names that are explicitly opted in. |
| `KOMODO_MCP_ACTOR` | Actor stamped on mutations. Default: `vogt-session:$VOGT_SESSION_ID`, or `komodo-mcp`. |

The flags `--allow-write`, `--protected` and `--allow-protected` override the matching variables. `--check` verifies config and connectivity. `--list-tools` prints the tool schemas.

## Build

```bash
cargo build --release -p komodo_mcp          # -> target/release/komodo-mcp
cargo test -p komodo_mcp -p names_diff       # redaction, allowlist, body shapes, mock-Core E2E
```

The fork's Core image (`scripts/tdd/core-only.Dockerfile`) also ships it at `/usr/local/bin/komodo-mcp`.

## Register it

Claude Code (user scope). The API key and secret are inherited from the session environment, so keep them out of the config file:

```bash
claude mcp add komodo --scope user \
  -e KOMODO_URL=http://100.92.54.45:3011 \
  -e KOMODO_MCP_WRITE_STACKS=vogt-dev \
  -- /usr/local/bin/komodo-mcp
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.komodo]
command = "/usr/local/bin/komodo-mcp"
env = { KOMODO_URL = "http://100.92.54.45:3011", KOMODO_MCP_WRITE_STACKS = "vogt-dev" }
# Pass the credentials through from the session rather than writing them here.
env_vars = ["HOMELAB_KOMODO_API_KEY", "HOMELAB_KOMODO_API_SECRET", "VOGT_SESSION_ID"]
```

Run `komodo-mcp --check` with the same environment to confirm it connects.

To let a session deploy prod, add `KOMODO_MCP_ALLOW_PROTECTED=vogt-prod` for that session only. A prod deploy recreates the vogt-prod pod and kills any session living in it.

## Typical flows

- **Bump a digest and deploy dev:** `read_stack_file` → edit → `write_stack_file` (refresh is automatic) → `deploy_stack` → `container_health`.
- **"What changed on vogt-prod since the last good deploy, and who?":** `stack_history(stack: "vogt-prod", since_last_successful_deploy: true)`, or `env_diff(stack: "vogt-prod", against: {last_successful_deploy: true})`.
