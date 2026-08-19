# TheDancingDeveloper Komodo fork

A fork of [moghtech/komodo](https://github.com/moghtech/komodo) that adds one capability: **Komodo stacks resolve secrets live from Infisical instead of holding copies that drift.**

## Why

Cadastre named the problem before this work started — Komodo *"has no external secret-manager connector, so Infisical values are COPIED into stack environments — a point-in-time copy, and the estate's main silent-staleness source."*

An audit of the live instance measured it: **180 literal credential copies across 74 stacks, and zero use of Komodo's own interpolation mechanism.** One secret is copied into as many as six stacks, so rotating it means six coordinated hand edits — and nothing detects when they are missed.

## What changed

A stack now holds a *reference*:

```diff
- POSTGRES_PASSWORD=<literal value pasted from Infisical>
+ POSTGRES_PASSWORD=[[infisical://apps/prod/HOMELAB_STACKARR_POSTGRES_PASSWORD]]
```

Rotating the value in Infisical takes effect on the next deploy, with no stack edit. The reference form matches the estate's existing Cadastre `secret_ref` convention.

Crucially, this does **not** make Komodo depend on Infisical being up. The last successfully read values are cached and persisted to disk — **encrypted with AES-256-GCM** — so Core can cold-start with Infisical completely unreachable and keep deploying. An outage costs freshness, not availability.

## Documents

| Document | What it covers |
|---|---|
| [`AUDIT-2026-08-18.md`](AUDIT-2026-08-18.md) | The measured scope of credential drift on Node B, and the two caveats on those numbers |
| [`DESIGN.md`](DESIGN.md) | How the integration works, and the failure-mode decisions that shaped it |
| [`DEPLOYMENT.md`](DEPLOYMENT.md) | Building the one image that is needed, and rolling it out via a canary |
| [`MAINTENANCE.md`](MAINTENANCE.md) | Staying at parity with upstream releases |
| [`CADASTRE.md`](CADASTRE.md) | Estate records this work invalidates or adds |

## Shape of the change

Six upstream files, **224 insertions, zero deletions**, plus one self-contained crate:

| File | Lines | Nature |
|---|---:|---|
| `lib/infisical/` | ~1400 | New crate — the provider |
| `lib/interpolate/src/lib.rs` | +185 | Fail-closed guard + tests |
| `bin/core/src/helpers/query.rs` | +11 | The hook |
| `bin/core/src/main.rs` | +12 | Startup validation |
| `bin/core/Cargo.toml`, `Cargo.toml` | +2 | Dependency wiring |

Purely additive, by design — that is what makes rebasing onto each upstream release cheap.

## Branches

| Branch | Role |
|---|---|
| `main` | Pristine upstream mirror. Never commit here. |
| `tdd/patches` | The canonical patch series — three commits |
| `tdd/release/v2.2.0` | Series rebased onto upstream v2.2.0 (currently deployed version) |
| `tdd/release/v2.3.2` | Series rebased onto upstream v2.3.2 (latest upstream) |

The series applies to both tags cleanly and passes its tests on both. See [`MAINTENANCE.md`](MAINTENANCE.md).

## Quick start

```bash
cargo test  -p interpolate -p infisical      # the guard is the safety-critical part
./scripts/tdd/build-core-image.sh            # build the one image Node B needs
./scripts/tdd/sync-upstream.sh               # rebase onto the newest upstream release
mydevenv2-agent-auth run -- python3 scripts/tdd/audit-komodo-secrets.py   # re-run the audit
```

## Status

| Item | State |
|---|---|
| Provider crate, guard, Core hook | Done — builds and tests pass on v2.2.0 and v2.3.2 |
| Last-known-good persistence (survives a Core restart) | Done — proven by `tests/cold_start.rs` |
| Snapshot encrypted at rest (AES-256-GCM) | Done — no secret value or name is readable on disk |
| Core image (`linux/amd64`) | Built — `komodo-core-infisical:2.2.0-infisical.3` |
| Deployed to Node B | **Not yet** — canary rollout is a human go/no-go, see [`DEPLOYMENT.md`](DEPLOYMENT.md) |
| Dedicated Infisical identity for Komodo | **Not yet** — needs Infisical org admin, cannot be done by an agent |
| Migrating the 180 literals | **Not started** — deliberately out of scope for this build |
| Cadastre records updated | **Not yet** — do it after the canary, see [`CADASTRE.md`](CADASTRE.md) |
