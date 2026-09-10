# Fork maintenance — staying at parity with upstream Komodo

This fork exists to add one capability (see [`DESIGN.md`](DESIGN.md)) while tracking upstream Komodo releases indefinitely. Everything below serves that second requirement.

## Branch model

| Branch | Base | Role |
|---|---|---|
| `main` | `upstream/main` | Pristine mirror of upstream. **Never commit here.** |
| `tdd/patches` | latest deployed upstream tag | The canonical patch series. Our changes and nothing else. |
| `tdd/release/v<tag>` | upstream tag `v<tag>` | `tdd/patches` rebased onto that tag. This is what gets built and deployed. |

Remotes:

```
origin    https://github.com/TheDancingDeveloper-org/komodo.git   (our fork)
upstream  https://github.com/moghtech/komodo.git                  (moghtech)
```

## Why rebase rather than merge

A merge-based fork accumulates merge commits and makes "what exactly did we change?" progressively harder to answer. A rebased patch series keeps that answer to a single command:

```bash
git log --oneline v2.2.0..tdd/patches
```

Twenty-one commits at the time of writing (the integration, its tests, the fork
docs, and the CI that keeps this parity going). That is the whole fork, and the
command above always shows exactly what we changed and nothing else.

## The design rules that keep rebasing cheap

These are not style preferences — they are the reason the series applied to v2.3.2 with zero conflicts.

1. **Additive only.** The patch series **deletes nothing from any upstream file** — every upstream file it touches, it only adds to (currently ~30 files, roughly 3,900 insertions). The only removals anywhere in the series are within our own CI workflows and docs.
2. **New code lives in a new crate.** `lib/infisical/` is ours alone and can never conflict.
3. **Never touch the config structs.** Provider configuration is read from the process environment rather than `CoreConfig`. This deliberately avoids `client/core/rs/src/entities/config/core.rs`, `bin/core/src/config.rs` and `config/core.config.toml`, the three highest-churn config files upstream. Resisting the "but it belongs in CoreConfig" instinct is what keeps this fork maintainable.
4. **One hook, not many.** The integration attaches at a single function (`get_variables_and_secrets`) that already backs all 12 interpolation call sites.
5. **Don't inherit optional workspace metadata.** Upstream removed `workspace.package.authors` in v2.3.2, which broke the crate manifest on the first rebase. Inherit only fields upstream is certain to keep.
6. **Keep our `Cargo.toml` additions in the trailing `# FORK` block.** Upstream bumps dependency versions throughout those lists on nearly every release, so any line of ours sitting next to a bumped line conflicts every single time. This was learned the hard way — `aws-lc-rs` and `zeroize` were originally added beside `rustls` and conflicted on the very next rebase.

## Routine upgrade

```bash
./scripts/tdd/sync-upstream.sh              # rebase onto the newest upstream release
./scripts/tdd/sync-upstream.sh v2.4.0       # or onto a specific tag
```

The script fetches upstream, rebases `tdd/patches` onto the target tag on a throwaway branch, and refuses to leave a half-finished rebase behind. It does not push and does not deploy.

Then verify before promoting:

```bash
cargo test -p interpolate -p infisical
cargo check -p komodo_core -p komodo_periphery
```

Only once that passes:

```bash
git branch -f tdd/release/v2.4.0 <the branch the script produced>
git push origin tdd/release/v2.4.0
```

## When a rebase conflicts

A conflict means upstream changed something the patch series touches. There are only a few such places, so diagnosis is quick:

| Conflict in | Likely cause | Fix |
|---|---|---|
| `bin/core/src/helpers/query.rs` | `get_variables_and_secrets` was refactored | Re-attach `infisical::extend_secrets(&mut secrets).await` after the secret Variables are merged, keeping it last |
| `bin/core/src/main.rs` | startup sequence reordered | Re-place the `preload()` call after `startup::on_startup()` |
| `lib/interpolate/src/lib.rs` | interpolation rewritten | Re-attach the guard immediately **before** the secrets pass; re-check `svi`'s escape rule still matches `unresolved_provider_token` |
| `Cargo.toml` / `bin/core/Cargo.toml` | upstream bumped a dependency version next to ours | Keep **upstream's** versions, re-add our lines. If ours were not already in the trailing `# FORK` block, move them there so it stops recurring |
| `Cargo.lock` | upstream bumped a dependency on the same line our `infisical` entry sits beside (the common case — happened on v2.3.3) | The lockfile is generated, so don't hand-tune it: resolve the marker by keeping **upstream's** version and re-adding our line, then run `cargo fetch` to make the whole file consistent again and commit it. The Upstream parity workflow does this refresh automatically after a clean rebase |

After resolving, **always** re-run `cargo test -p interpolate`. The escape-handling tests are the ones that catch a silently broken guard, which is the dangerous failure mode: a broken guard does not error, it lets a literal token through into a deployment.

## Rebase history

| Date | From | To | Result |
|---|---|---|---|
| 2026-08-18 | `v2.2.0` | `v2.3.2` | Zero conflicts. One fix needed: upstream removed `workspace.package.authors`, so the crate manifest stopped inheriting it. |
| 2026-08-19 | `v2.2.0` | `v2.3.2` | One conflict, in `Cargo.toml`: our `aws-lc-rs`/`zeroize` lines sat beside `rustls`, `uuid` and `data-encoding`, all of which upstream bumped. Resolved by keeping upstream's versions and re-adding ours — then fixed properly by moving both into the trailing `# FORK` block so it cannot recur. Builds and passes all 30 tests on both tags. |
| 2026-09-10 | `v2.2.0` | `v2.3.3` | One conflict, in `Cargo.lock` only — `Cargo.toml` auto-merged cleanly, so the `# FORK` block held. Upstream bumped `indexmap` 2.14.0 → 2.14.1 on the line our `infisical` entry sits beside; resolved by keeping 2.14.1 and re-adding `infisical`, then regenerating the lockfile with `cargo fetch` (which also picked up `reqwest` 0.13.3 → 0.13.4 and upstream dropping `urlencoding`/`formatting`). `cargo fmt`, `cargo test -p interpolate -p infisical` (8 guard tests), and `cargo check` on Core + Periphery all pass. Branch `tdd/rebase/v2.3.3` ready to promote. |

## Contributing upstream

The `interpolate` guard is arguably an upstream bug fix independent of Infisical: `fail_on_missing_variable = false` silently passes unresolved tokens into deployments. If offered upstream, generalise the prefix check rather than hardcoding `infisical://`.
