# Estate implications (Cadastre)

Cadastre is the estate's land register. This fork changes facts it records, so those records need updating. Cadastre is a map, not a control plane — it never deploys anything, and it will not notice this change on its own.

## 1. The `komodo` service note becomes false

Cadastre currently declares, on `service:komodo`:

> …**It has no external secret-manager connector, so Infisical values are COPIED into stack environments — a point-in-time copy, and the estate's main silent-staleness source.**

That sentence is the justification for this entire piece of work, and it stops being true the moment the new Core image is deployed. Leaving it in place is worse than never having written it: an agent reading Cadastre would conclude the drift problem is unsolved and might "fix" it again by copying values in.

Update it once the canary is proven, not when the image is built.

Suggested replacement:

> GitOps deploy controller, core on Node B with peripheries on Node B, Hetzner, Vultr and hetzner3. Production deploys go through it, never ad hoc SSH. Runs a forked Core (`TheDancingDeveloper-org/komodo`) that resolves secrets live from Infisical at deploy time via `[[infisical://<project>/<env>/<KEY>]]` references, so stacks hold references rather than copies. Stacks still holding literal values are pre-migration leftovers, not the intended pattern.

## 2. A new hard runtime dependency

`komodo depends_on infisical` is now true and should be declared.

This is a genuinely new failure mode and worth stating plainly rather than burying:

- Before: Infisical down ⇒ deploys unaffected (values were already copied in).
- After: Infisical down ⇒ deploys **that reference Infisical** fail once the cache's stale window expires.

Mitigations already in the design: a TTL cache, a bounded serve-stale window, and localised failure so only resources that actually reference a token are affected. But the dependency is real.

It also carries **shared-fate risk**: Komodo Core and Infisical both run on `node-b`. Losing that host loses both, and the deploy controller cannot be used to recover the secret store it depends on. That is not a reason to avoid the integration — the drift it removes is a daily problem, whereas this is a host-loss problem — but it should be a declared, known property rather than a surprise during an incident.

## 3. A new secret to declare

Komodo consumes a new credential: its own Infisical machine identity.

- `komodo consumes_secret homelab-komodo-infisical-client-id`
- `komodo consumes_secret homelab-komodo-infisical-client-secret`

Both live in Infisical `apps/prod`. Per [`DEPLOYMENT.md`](DEPLOYMENT.md) this must be a **dedicated read-only identity**, not the `mydevenv2-agents` identity, which holds read/write admin on `apps` and `cicd`.

## 4. The token form already matches the convention

Cadastre declares this `secret_ref` convention:

```
^(infisical|woodpecker)://[a-z0-9-]+/[a-z0-9-]+/[A-Za-z0-9_]+$
```

The token form was chosen to match it, and `lib/infisical/src/config.rs` validates the alias and environment charset at startup, so every reference this fork can resolve satisfies the convention by construction.

Verified 2026-08-18 — a compose file using the reference form passes cleanly:

```
cadastre check --kind compose <file>
  findings: 0 error, 0 warn, 0 info
```

(The only `unchecked` note was the unrelated, pre-existing `x-cadastre: {host: ...}` placement hint.)

## 5. Drift detection becomes possible

This is the upside worth recording. Today Cadastre's `secrets-apps` / `secrets-cicd` / `secrets-infrastructure` collectors can see which secrets *exist*, but nothing can see which stacks *use* them — the values are opaque literals in Komodo's MongoDB, indistinguishable from any other string.

Once stacks carry references, usage becomes machine-readable: a collector can parse `infisical://<project>/<env>/<KEY>` out of a stack environment and answer questions that are structurally impossible today —

- which secrets are referenced by nothing (candidates for deletion),
- which references point at a key that no longer exists (a deploy that will fail closed at the next attempt),
- which service consumes which secret, without a human maintaining the mapping by hand.

Worth considering as a follow-on collector once the migration is under way.

## 6. Do this only after the canary

Cadastre records what *is*, not what is intended. Update these records after the canary stack in [`DEPLOYMENT.md`](DEPLOYMENT.md) is proven, not when the image is built — otherwise the register describes a state the estate is not yet in, which is the exact failure mode it exists to prevent.
