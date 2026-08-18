# Komodo → Infisical secret integration — design

## Problem

Komodo stacks hold *copies* of secret values. Infisical holds the *source of truth*. Nothing links them, so the copies drift silently. See [`AUDIT-2026-08-18.md`](AUDIT-2026-08-18.md) for the measured scope: 180 literal credential copies across 74 stacks, and zero use of Komodo's own interpolation mechanism.

## Goal

A stack should reference a secret, never contain one. Rotating a value in Infisical should take effect on the next deploy with no stack edit.

## The key insight

Komodo already has everything needed except the connector. Its interpolator (`svi`, `Interpolator::DoubleBrackets`) resolves `[[TOKEN]]` by **exact-match lookup in a `HashMap<String, String>`**:

```rust
match (variables.get(variable), fail_on_missing_variable) { ... }
```

So an Infisical integration does **not** need new syntax, a new parser, a UI change, or a database migration. It only needs to put more entries into the map that Core already builds. That is the entire integration.

## Token form

```
[[infisical://<project-alias>/<environment>/<SECRET_KEY>]]
```

For example:

```
POSTGRES_PASSWORD=[[infisical://apps/prod/HOMELAB_STACKARR_POSTGRES_PASSWORD]]
```

This shape is not arbitrary — it matches the estate's **already-declared Cadastre `secret_ref` convention**:

```
^(infisical|woodpecker)://[a-z0-9-]+/[a-z0-9-]+/[A-Za-z0-9_]+$
```

`config.rs` validates the alias and environment charset at startup, so every token this fork can resolve is valid against that convention by construction. A stack file therefore carries a secret reference that Cadastre can already parse and check.

`<project-alias>` is a short stable name (`apps`), deliberately decoupled from the Infisical project *slug* (`apps-lj-ns`), whose random suffix would be unpleasant to write into stack files and would change if the project were recreated.

## Where it hooks

`bin/core/src/helpers/query.rs::get_variables_and_secrets()`.

That single function is called from **12 sites, all inside `bin/core`**, and it backs every interpolation path — Stacks, Deployments, Builds, Repos, Actions and all alerters. One hook covers the entire surface.

```
get_variables_and_secrets()
  |-- core_config().secrets          (upstream)
  |-- secret Variables from Mongo    (upstream)
  +-- infisical::extend_secrets()    (this fork)  <- merged last
```

Provider secrets are merged **last** so an operator can shadow one with a Core secret or a secret Variable of the same name during an incident — a deliberate manual override path.

Because the entries land in the *secrets* half of the map rather than the *variables* half, Komodo's existing redaction applies unchanged: values are stripped from logs and only the token name is shown.

## Failure behaviour

This is the part that needed care, and it drove two non-obvious decisions.

### 1. An unresolved reference must never reach a deployment

`svi` is called with `fail_on_missing_variable = false`. An unknown token is left in the output **verbatim**. Without a guard, a failed Infisical lookup would deploy the literal string `[[infisical://apps/prod/DB_PASSWORD]]` as the password — and the deploy would report success.

`lib/interpolate` therefore refuses to interpolate a target containing an `infisical://` reference the secrets map cannot resolve.

The check runs on the **input** to the secret-interpolation pass, not its output, because the output is ambiguous: `svi` renders both an escaped literal `[[[infisical://x]]]` and an unresolved reference `[[infisical://x]]` as the same text. Only the input distinguishes them. The scan mirrors `svi`'s `[[` splitting and leading-`[` escape rule, and unit tests pin that correspondence.

### 2. A provider outage must not fail everything

`get_variables_and_secrets` also feeds **every alerter**. Making a provider outage fail that function would suppress the very alerts telling you Infisical is down.

So the failure is localised rather than global:

| Layer | On provider failure |
|---|---|
| `infisical::extend_secrets` | Logs loudly, contributes nothing. Never returns an error. |
| `interpolate` guard | Fails **only** resources that actually reference an `infisical://` token. |
| Everything else | Deploys and alerts normally. |

### 3. Bounded staleness beats a hard outage

Secrets are cached for `KOMODO_INFISICAL_CACHE_TTL_SECONDS` (default 300). If a refresh fails but a previous snapshot is younger than `KOMODO_INFISICAL_STALE_MAX_SECONDS` (default 3600), the cached snapshot is served with a warning. An Infisical restart should not instantly fail every deploy in the estate; the window is bounded and configurable.

### 4. Startup validation is non-fatal on purpose

Core validates configuration and warms the cache at boot, so a misconfiguration is reported immediately rather than surfacing hours later as a confusing deploy failure. It does **not** crash on failure: Core and Infisical run on the same host, so crashing would create a boot-order dependency and a crash loop whenever both restart together.

### 5. Hidden values are skipped, not blanked

If the Komodo identity may list a secret but not read it, Infisical returns `secretValueHidden: true`. Such entries are skipped with a warning so the token stays unresolved and the guard fails the deploy — far better than substituting an empty string for a password.

## Configuration

Read from the process environment, **not** from `CoreConfig`. This is deliberate: it avoids touching `client/core/rs/src/entities/config/core.rs`, `bin/core/src/config.rs` and `config/core.config.toml` — the three highest-churn config files upstream — which is what keeps the patch series cheap to rebase. See [`MAINTENANCE.md`](MAINTENANCE.md).

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `KOMODO_INFISICAL_ENABLED` | no | `false` | Master switch. Unset means Core behaves exactly like upstream. |
| `KOMODO_INFISICAL_URL` | yes | — | Infisical base URL. |
| `KOMODO_INFISICAL_CLIENT_ID` | yes | — | Universal-auth machine identity ID. |
| `KOMODO_INFISICAL_CLIENT_SECRET` | yes | — | Universal-auth machine identity secret. |
| `KOMODO_INFISICAL_PROJECTS` | yes | — | `alias=projectId` pairs, comma separated. |
| `KOMODO_INFISICAL_ENVIRONMENTS` | no | `prod` | Environment slugs, comma separated. |
| `KOMODO_INFISICAL_SECRET_PATH` | no | `/` | Infisical folder path. |
| `KOMODO_INFISICAL_CACHE_TTL_SECONDS` | no | `300` | Cache freshness window. |
| `KOMODO_INFISICAL_STALE_MAX_SECONDS` | no | `3600` | How long a stale snapshot may be served if refresh fails. Must be >= the TTL. |
| `KOMODO_INFISICAL_TIMEOUT_SECONDS` | no | `15` | HTTP timeout. |

Every credential variable also accepts a `_FILE` suffix (`KOMODO_INFISICAL_CLIENT_SECRET_FILE`), which is the preferred deployment form — the credential arrives as a mounted file rather than an environment variable readable by anything that can inspect the container environment.

## Scope of change

| File | Lines | Nature |
|---|---:|---|
| `lib/infisical/` | ~700 | New crate |
| `lib/interpolate/src/lib.rs` | +185 | Guard + tests |
| `bin/core/src/helpers/query.rs` | +11 | The hook |
| `bin/core/src/main.rs` | +12 | Startup preload |
| `bin/core/Cargo.toml` | +1 | Dependency |
| `Cargo.toml` | +1 | Workspace member |

**Zero deletions from upstream files.** The patch is purely additive.

## What is intentionally *not* changed

- **Periphery** — interpolation is Core-only, so Periphery keeps running the stock upstream image. Only Core is rebuilt.
- **The UI** — no new screens. Tokens are typed into the existing environment field.
- **The database** — no migration, no new collection.
- **`CoreConfig`** — see above.

## Known limitation

When a resource has a variables pass (i.e. non-secret Variables exist), interpolation runs twice, and the first pass consumes the `[[[x]]]` escape into `[[x]]`. The second pass therefore sees a live reference. Escaping a literal provider token is only reliable on resources with no variables pass. This is a pre-existing `svi` double-pass quirk, not new behaviour; failing closed is the safe direction for the ambiguity, and it is pinned by a unit test.
