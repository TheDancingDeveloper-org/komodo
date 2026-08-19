# Building and deploying Komodo Core with the Infisical provider

## Scope: one image, one container

Only **Komodo Core** is rebuilt. That is not an optimisation, it follows from where the code changed:

- Secret interpolation happens entirely in Core. All 12 call sites of `get_variables_and_secrets` are in `bin/core`.
- Every **Periphery** in the estate — on `node-b`, `hetzner`, `hetzner3`, `vultr` — keeps running the stock upstream image. They are untouched, which keeps the blast radius of this fork to a single container.
- The **UI** is pulled from the version-matched upstream image (`ghcr.io/moghtech/komodo-ui:<version>`) rather than rebuilt. This fork does not change the UI.
- `node-b` is `x86_64`, so a single `linux/amd64` image is built. No multi-arch, no QEMU.

## Build

```bash
./scripts/tdd/build-core-image.sh            # build and tag
./scripts/tdd/build-core-image.sh --push     # and push to the registry
```

Produces `repo.indexarr.net/indexarr/komodo-core-infisical:<upstream-version>-infisical.<n>`.

### A caution about where this builds

Inside MyDevEnv2, `docker` is **Node B's own daemon** — same daemon ID, same `/var/lib/docker`, same disk. Confirm before building:

```bash
docker info --format '{{.ID}}'
tailscale ssh sprooty@winrarhost 'docker info --format "{{.ID}}"'   # same ID => same daemon
```

Node B's root disk is the estate's tightest resource and Cadastre asks that it stay well under 80%. It has been observed at 90%. The build script refuses to start with less than 40G headroom where it can measure it, but **it cannot measure from inside MyDevEnv2** (only the socket is mounted, not the data directory) and will say so. Check by hand:

```bash
tailscale ssh sprooty@winrarhost 'df -h /'
```

Reclaim afterwards:

```bash
docker builder prune -f
```

## Prerequisite: a dedicated Infisical machine identity

Komodo Core needs its **own** universal-auth identity. Do not reuse `mydevenv2-agents`: that identity holds **read/write admin** on `apps` and `cicd`, and Komodo needs only read.

This step needs Infisical org admin and **cannot be done by an agent** with the credentials agents hold.

- Name: `komodo-core`
- Auth method: universal auth
- Access: **read-only (`viewer`)** on `apps`, `cicd`, `infrastructure`
- Store the resulting credentials in Infisical `apps/prod` as `HOMELAB_KOMODO_INFISICAL_CLIENT_ID` and `HOMELAB_KOMODO_INFISICAL_CLIENT_SECRET`

Least privilege matters more than usual here: this identity can read every secret the provider is scoped to, and it lives on the box that also runs Infisical.

## Configuration

Komodo Core is deployed from a **host-level compose file on Node B**, outside Komodo itself:

```
/home/sprooty/stacks/komodo/docker-compose.yml     (project: komodo)
```

That is deliberate and worth preserving — Komodo cannot safely redeploy its own Core, so this file is edited and applied on the host.

Add to the `komodo-core` service:

```yaml
    environment:
      KOMODO_INFISICAL_ENABLED: "true"
      KOMODO_INFISICAL_URL: "http://192.168.1.75:8400"
      KOMODO_INFISICAL_PROJECTS: "apps=76b1ebe1-3656-4cef-952c-30d5d489c6e7,cicd=6d6caff5-7aaf-42f8-a135-2455d7629af8,infrastructure=5b7e75de-e874-484d-9595-873acd6bfd07"
      KOMODO_INFISICAL_ENVIRONMENTS: "prod"
      KOMODO_INFISICAL_CLIENT_ID_FILE: "/run/secrets/infisical_client_id"
      KOMODO_INFISICAL_CLIENT_SECRET_FILE: "/run/secrets/infisical_client_secret"
      KOMODO_INFISICAL_CACHE_FILE: "/var/lib/komodo/infisical-cache.json"
    volumes:
      - komodo-secret-cache:/var/lib/komodo
```

and alongside the existing `komodo-keys` / `periphery-keys` entries:

```yaml
volumes:
  komodo-secret-cache:
```

**Set `KOMODO_INFISICAL_CACHE_FILE`.** Without it the cache is in-memory only, which means Core cannot cold-start while Infisical is down — a hard dependency between two services that run on the same host. With it, Core boots from the last-known-good snapshot and keeps deploying. See `DESIGN.md` for the staleness policy and the plaintext-on-disk trade-off this accepts.

Use a dedicated volume rather than reusing `komodo-keys`: this file holds every secret the provider is scoped to, and it is easier to reason about, back up and destroy on its own.

Prefer the `_FILE` form. It keeps the credential out of the container environment, where anything able to inspect the container can read it.

Use the **direct LAN or tailnet** Infisical endpoint, not `https://se.sprooty.com/`, which is Caddy/basic-auth gated from some runtimes.

Project IDs are identifiers, not secrets.

## Rollout — canary, not big-bang

The image changes how *every* stack resolves secrets, so prove it on one stack first.

**1. Pin the new image and restart Core.**

```yaml
image: repo.indexarr.net/indexarr/komodo-core-infisical:2.2.0-infisical.1
```

```bash
tailscale ssh sprooty@winrarhost \
  'cd /home/sprooty/stacks/komodo && docker compose up -d komodo-core'
```

**2. Confirm the provider came up.** Startup validation is non-fatal by design, so a broken configuration shows here as a log line rather than a crash. Check for it explicitly:

```bash
tailscale ssh sprooty@winrarhost \
  'docker logs komodo-core 2>&1 | grep -i infisical'
```

Expect `Infisical secret provider enabled` and `Loaded secrets from Infisical`. Anything else means the provider is not working, even though Core is up and serving.

**3. Confirm existing stacks are unaffected.** No stack uses `[[...]]` today (see the audit), so nothing should change. Deploy one untouched stack and confirm it behaves exactly as before.

**4. Convert one low-risk stack.** Replace a literal with a reference:

```diff
- POSTGRES_PASSWORD=<literal value>
+ POSTGRES_PASSWORD=[[infisical://apps/prod/HOMELAB_STACKARR_POSTGRES_PASSWORD]]
```

Deploy it. In the update log, Komodo reports `Interpolate Secrets -> replaced: infisical://apps/prod/...` and **never** the value.

**5. Prove it fails closed.** This is the check worth doing deliberately, because the failure it guards against is silent:

```
TEST=[[infisical://apps/prod/DEFINITELY_NOT_A_REAL_KEY]]
```

The deploy must **fail** with `unresolved secret reference`. If it instead succeeds and the container receives the literal string `[[infisical://...]]`, the guard is not working — stop and investigate before converting anything else.

**6. Prove it survives an Infisical outage.** This is the step that verifies the dependency is actually soft. With a converted stack deployed and working:

```bash
# Confirm the snapshot has been persisted
tailscale ssh sprooty@winrarhost \
  'docker exec komodo-core sh -c "ls -l /var/lib/komodo/infisical-cache.json"'

# Stop Infisical, restart Core so nothing is cached in memory, redeploy
tailscale ssh sprooty@winrarhost 'docker stop infisical && docker restart komodo-core'
```

Core's log should show `Restored the last-known-good Infisical snapshot from disk` and `Started with the last known good Infisical secrets`, and the converted stack should still deploy. Start Infisical again afterwards and confirm the log returns to `Loaded secrets from Infisical`.

Choose the timing: this stops the estate's secret store briefly.

## Rollback

The image is the only change on the Komodo side, and the provider is inert unless `KOMODO_INFISICAL_ENABLED` is true. Two levels:

| Situation | Action |
|---|---|
| Provider misbehaving, stacks not yet converted | Set `KOMODO_INFISICAL_ENABLED: "false"` and restart Core. The build is then byte-equivalent to upstream in behaviour. |
| Need the upstream image back | Restore `image: ghcr.io/moghtech/komodo-core:2` and `docker compose up -d komodo-core`. |

Note the ordering constraint: once a stack has been converted to references, rolling back to the upstream image leaves that stack unable to resolve its secrets — upstream will pass the literal token straight through, with no guard. **Convert stacks only after the image has been stable for a while, and revert conversions before reverting the image.**
