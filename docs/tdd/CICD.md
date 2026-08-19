# CI/CD — building the image and holding parity with upstream

Two GitHub Actions workflows, running on the estate's own self-hosted runners.

## Why GitHub Actions and not Woodpecker

Woodpecker runs all of this estate's CI, but it is **OAuth'd to Forgejo** and this fork lives on GitHub. Mirroring the repo into Forgejo purely to reach Woodpecker would add a sync to keep correct, for no gain.

The org already has five self-hosted runners registered, including two labelled `publish` on `node-b` with `docker` and `tailnet` access — which is exactly what publishing to `repo.indexarr.net` needs. Both workflows follow the house pattern used by `rustnzb`.

| Runner | Labels |
|---|---|
| `node-b-gha-public-publish`, `-2` | `self-hosted, Linux, X64, node-b, rust, docker, publish, tailnet` |
| `node-b-gha-public-rust` | `self-hosted, Linux, X64, node-b, rust, docker, tailnet` |
| `proxmox-gha-public-rust`, `wsl2-gha-public-rust` | `self-hosted, Linux, X64, rust` |

## `Core image` — build and publish

**Triggers:** push to `tdd/patches` or `tdd/release/**`, or manual dispatch.

Two jobs:

1. **test** (`rust` runner) — `cargo fmt` on the fork-owned crates, the full test suite, an explicit re-run of the fail-closed guard test on its own, then `cargo check` on both binaries. Cheap, and it catches an upstream API change before ten minutes of image build.
2. **image** (`publish` runner) — builds `scripts/tdd/core-only.Dockerfile` for `linux/amd64` and pushes to `repo.indexarr.net/indexarr/komodo-core-infisical`.

Tags published:

| Tag | Purpose |
|---|---|
| `<upstream-version>-infisical` | Moving — newest build for that upstream release |
| `<upstream-version>-infisical-<sha>` | Immutable — what you pin in the compose |

Pin the **sha tag** in `/home/sprooty/stacks/komodo/docker-compose.yml`. The moving tag is for convenience, not for production.

Three deliberate choices:

- **`cargo fmt` is scoped to `-p infisical -p interpolate`.** `--all` would gate our CI on upstream's formatting, which we do not control and must not fight.
- **The Rust toolchain is pinned to the version the Dockerfile builds with**, so CI cannot pass on a compiler the image will not use.
- **Docker Hub is authenticated first.** The build pulls `rust`, `debian` and `deno` base images from it, and unauthenticated pulls hit the shared runner's rate limit.

## `Upstream parity` — stay level with moghtech/komodo

**Triggers:** daily at 14:17 UTC, or manual dispatch with an optional target tag.

What it does:

1. Fetches upstream tags and works out the release tag the patch series currently sits on, versus the newest upstream release. Prereleases (`-dev-N`) are ignored — they are not parity targets.
2. If they match, it stops. Most days are a no-op.
3. Otherwise it replays the series onto the new tag and verifies it: formatting, tests (including the fail-closed guard), and `cargo check` on both binaries.
4. **Clean →** pushes `tdd/rebase/<tag>` and opens a PR into `tdd/patches`.
   **Conflicted or failing →** opens an issue naming the conflicted files and pointing at the conflict table in [`MAINTENANCE.md`](MAINTENANCE.md), and fails the run.

Both paths are idempotent: an existing open PR or issue is not duplicated on the next run.

**Nothing is merged, promoted or deployed automatically.** The workflow's job is to tell you promptly whether upstream still applies, not to move production. A clean rebase is not a working deployment — the PR body says so, because both defects found in this fork so far were invisible to the test suite and only appeared against a live Core (see [`CANARY-2026-08-19.md`](CANARY-2026-08-19.md)).

## Secrets

Repo-level, sourced from Infisical:

| GitHub secret | Infisical source | Used for |
|---|---|---|
| `FORGEJO_TOKEN` | `cicd/prod/FORGEJO_TOKEN` | Push to `repo.indexarr.net` |
| `DOCKERHUB_USERNAME` | `apps/prod/HOMELAB_SECSCAN_DOCKERHUB_USERNAME` | Base image pull rate limit |
| `DOCKERHUB_TOKEN` | `cicd/prod/DOCKEHUB_PAT_sprooty` | Base image pull rate limit |

These are copies, and will drift if the Infisical originals are rotated — the same class of problem this fork exists to fix, one layer up. Re-run the setup in this document's history after any rotation. GitHub Actions has no equivalent of the reference mechanism, so this is a genuine and accepted limitation, not an oversight.

## Deploying a published image

CI builds and publishes; it does **not** deploy. Komodo Core is deployed from a host compose file on `node-b`, deliberately outside Komodo itself, so it cannot restart itself mid-deploy:

```bash
# on node-b, in /home/sprooty/stacks/komodo
#   image: repo.indexarr.net/indexarr/komodo-core-infisical:<version>-infisical-<sha>
docker compose up -d core
docker logs komodo-core 2>&1 | grep -i infisical
```

Then re-run the canary checks in [`CANARY-2026-08-19.md`](CANARY-2026-08-19.md).
