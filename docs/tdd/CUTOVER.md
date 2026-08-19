# Cutover plan — converting the remaining stacks

**Status at 2026-08-19:** 1 of 74 stacks converted (`personal-egressd-speedtest`). This plan covers the rest.

## What the estate actually holds

Every literal in every stack was compared against Infisical **by value**, not by name. That distinction matters: most values *are* already in Infisical, just under a different key.

| Class | Count | Meaning | Work |
|---|---:|---|---|
| **A** | 26 | Same name, same value in Infisical | Mechanical — reference it |
| **B** | 93 | Different name, same value | Reference it under the Infisical name |
| **C** | 47 | Value not in Infisical at all | Create the secret first |
| — | 147 | Non-secret config (`*_ENABLED`, `*_DIR`, `*_URL`, emails) | Leave alone |

**119 of 166 (72%) need no new secrets** — only a reference and a redeploy.

The C class splits further:

- **3 are real drift** — the name exists in Infisical but the running value differs. These are the problem this whole project exists to fix, caught in the act:
  - `grafanaloki` / `OMADA_PASSWORD` vs `infrastructure/prod`
  - `poc-identity` / `FORGEJO_ADMIN_PASSWORD` vs `infrastructure/prod`
  - `prod-mydevenv2` / `MYDEVENV2_TOKEN` vs `apps/prod`
- **44 are absent from Infisical entirely** and must be created before conversion.

## Recommended sequence

### Phase 0 — remove the single point of fragility (do first, 5 min)

The Core image exists **only in Node B's local daemon** (`pull_policy: never`); it was never pushed. If that daemon loses its images, Komodo Core will not start. Push it to a registry and switch the compose to a pull-able reference before converting anything else.

### Phase 1 — the 26 A-class (low risk, high confidence)

Hash-verified identical to Infisical, so conversion cannot change running behaviour. This is exactly what the canary was. Convert in batches by stack, redeploy, verify.

### Phase 2 — the 93 B-class, in three sub-groups

Not uniformly safe. The mapping quality varies and needs triage:

- **Unambiguous** — one candidate, names obviously correspond (`MYSQL_ROOT_PASSWORD` → `HOMELAB_ARR_MYSQL_ROOT_PASSWORD`). Convert like Phase 1.
- **Ambiguous (~11)** — the value exists under *several* Infisical names, so a human must choose which one this stack should follow. Examples: `personal-arr/SONARR_API_KEY` matches both `apps/prod/HOMELAB_ARR_SONARR_API_KEY` and `infrastructure/prod/DOCS_SONARR_API_KEY`; `GITHUB_RUNNER_PAT` (×3 stacks) matches both `HOMELAB_VOGT_GITHUB_TOKEN` and `GITHUB_DANCINGDEVELOPER_PAT`. Picking wrong silently couples two services to one rotation.
- **Credential reuse (~4)** — the value is shared across genuinely unrelated services. **Do not convert these as-is**: pointing both at one Infisical secret makes the reuse permanent and invisible. Mint distinct secrets instead.
  - `dev-mydevenv2/MYDEVENV2_ASSISTANT_API_KEY` and `feat-aidevenv/HARNESS_API_KEY` both equal `HOMELAB_PINGRAG_CLAWBAY_API_KEY`
  - `prod-1rok/CLAWBAY_API_KEY` actually equals `HOMELAB_MYAIAGENT_OPENAI_API_KEY` — the name and the value disagree about what this credential *is*
  - `personal-arr`: `MYSQL_PASSWORD` equals `MYSQL_ROOT_PASSWORD` — the application user holds the root password

### Phase 3 — the 3 drift cases

Each needs a human decision: is the running value correct, or the Infisical one? Converting without deciding will change the running configuration on next deploy. Reconcile in Infisical first, then convert.

### Phase 4 — the 44 absent secrets

Create in Infisical, then convert. Note the write boundary: the agent identity has **admin on `apps` and `cicd`** but only **viewer on `infrastructure`** — anything belonging there needs a human or a role change.

### Phase 5 — stop the bleeding

Nothing prevents a new literal being pasted into a stack tomorrow. Worth a periodic check (the audit script already detects it) or a Cadastre rule, otherwise the estate drifts back.

## Ordering and blast radius

Convert in increasing order of risk: `poc-*` and `down` stacks → `personal-*` → `prod-*`.

Three stacks need deliberate handling:

| Stack | Why |
|---|---|
| `prod-mydevenv2` | Redeploying it **terminates the agent session doing the work**. Must be done from another session, or accepted as the last action. |
| `vogt`, `vogt-dev` | Restarting these drops the Vogt MCP mid-task. |
| `komodo` (Core itself) | Not Komodo-managed; host compose only. Unaffected by stack conversion. |

## Redeploy policy — decide this explicitly

Converting a stack's environment is **inert until that stack is next deployed**. Two options:

- **Convert and redeploy together (recommended).** Failures surface immediately, under supervision. Costs one service restart per stack.
- **Convert and let each stack pick it up naturally.** No restarts now, but a bad reference lies dormant and then fails someone else's unrelated deploy weeks later. Fails closed and loudly — but at the worst moment.

## Effort

Roughly 40 stacks carry the 119 mechanical conversions. The conversion script (`scripts/tdd/`) already does the hash-verify-then-rewrite safely and refuses to convert anything whose value does not match. The real cost is the redeploys and watching them, not the edits.
