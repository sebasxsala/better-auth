# Cross-cutting documentation and product-alignment backlog

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture everything that **does** make sense to ship after excluding risky or out-of-scope code changes: shared operational docs, adapter README clarifications, and a single **product/upstream alignment backlog** for coordination — without client libraries, without embedding CORS in gems, and without speculative core refactors.

**Architecture:** Adds one repo-level feature doc for host responsibilities; touches existing package READMEs and `.docs/features/*` only where the omission lists explicitly called for **documentation** as the mitigation; creates **one** backlog file so deployment quirks and future parity debates stay grouped instead of scattered across package tickets.

**Tech Stack:** Markdown only (no application code in this plan).

**Relationship:** Complements `.docs/plans/2026-05-03-1515--api-key-hardening-plan.md` (API key code tasks). This plan does **not** repeat those items.

**Execution note (2026-05-05):** Compared the documentation claims against
upstream v1.6.9 and implemented the markdown-only items that matched the Ruby
package boundaries. Commit steps remain unchecked because the worktree already
contained many unrelated user changes and package guidance says not to commit
unless explicitly requested.

**Code follow-up (2026-05-05):** After explicit approval to include previously
deferred behavior changes, aligned SCIM-created users with upstream by removing
the Ruby-only `emailVerified: true` assignment. New SCIM users now keep the core
default `emailVerified: false`; existing linked users keep their stored state.

---

## Explicitly not implementation (summary table)

These remain **out of scope for code** in this repository wave; they are either referenced in the backlog doc (coordination) or intentionally omitted.

| Area | Item | Why |
|------|------|-----|
| Core / deployment | `trusted_origins: []` as strict “deny all” | Requires agreed merge semantics in `better_auth` configuration; not an adapter-only hack. |
| Gems | CORS inside any gem | Belongs to host Rack stack / reverse proxy. |
| Hanami / Rails | Rails-style `MountedApp` rewrite without proof | Could break Hanami; document constraints instead. |
| Hanami | Blind relation overwrite / inflector changes | Destructive or unclear contract; README-only caution. |
| Core | `debugLogs`-style parity | No thin equivalent without extending public/core APIs. |
| Mongo adapter | Transactions / replica sets | Server limitation; apps already use `transaction: false`; expand README only. |
| Mongo adapter | Harden `ObjectId` rescues everywhere | Risks compatibility; upstream is permissive on several paths. |
| Mongo adapter | Micro-fix `require "mongo"` ordering | Low value vs regression risk. |
| Redis storage | Custom error layer, Cluster CI, fractional TTL parity with Node, breaking `key_prefix: ""` default | Operational or marginal gains; document `key_prefix` opt-in risk instead of breaking change. |
| SCIM | Pagination RFC, Group/Bulk, advanced filters | Product expansion; separate certification-oriented plan. |
| SCIM | Change `emailVerified` on provision | Implemented after explicit approval; Ruby now keeps the upstream default `emailVerified: false` for newly provisioned SCIM users. |
| SCIM | `delete_user` vs unlink-only SCIM delete | Data model change across adapters. |
| SCIM | Composite unique index in core schema | Lives in core migrations per adapter; README/feature doc **recommendation** only. |
| SCIM | Timing hardening in **all** token adapters | Focus stays documented; wholesale adapter sweep deferred. |
| Sinatra | CSRF in gem, Rails changes, full route enumeration without core API, magical DDL transactions, rich SQL lexer | Wrong layer or huge scope; document boundaries. |
| Sinatra | Bearer/JWT on arbitrary routes via helpers only | Needs Session/Router-level design; document current cookie-centric helpers. |
| Sinatra | Universal `SCRIPT_NAME` normalization | Document mounting caveats only. |
| SSO | `private_key_jwt` / mTLS, full SLO/XML rewrite, lazy `ruby-saml` load, splitting `plugins/sso.rb` | Large or refactor-only; other deliveries. |
| SSO | Parity for `disable_implicit_sign_up` vs upstream | Product behavior change; needs decision. |
| SSO | Tiny housekeeping (`needs_runtime_discovery?` duplication, unused gemspec logger) | Track in backlog as nitpick if desired. |
| Multi-package | Portable PK DDL rewrite, native UUID migration columns, breaking secret defaults without migration story, whole-suite negative-path QA, strict `OptionBuilder` validation | Cross-cutting releases or test-policy decisions — backlog entries, not this doc sprint. |
| Passkey | UV enforcement vs upstream defaults, non-`none` attestation, distinct update-passkey ownership message, TS-identical `deviceType`/user handle bytes, flipping verify route to 401 for all failures | Product/upstream alignment or intentional Ruby/WebAuthn gem mapping; see backlog. |

---

## File map

| File | Action |
|------|--------|
| `.docs/features/host-app-responsibilities.md` | **Create** — CORS, origin validation vs middleware, CSRF ownership, optional Bearer caveats pointer. |
| `packages/better_auth/README.md` | **Modify** — Short pointer: `trusted_origins` merge behavior; empty array not “strict deny” unless core documents otherwise (link to host-app doc). |
| `packages/better_auth-hanami/README.md` | **Modify** — Mounting, regeneration, `trusted_origins` deployment note (do not rely on Hanami-only merge for strict-empty semantics). |
| `packages/better_auth-sinatra/README.md` | **Modify** — Mount + `SCRIPT_NAME` caveats; helpers scope (sessions/cookies); SQL migration helper constraints (no full lexer). |
| `packages/better_auth-rails/README.md` | **Modify** — Align `trusted_origins` / env deployment paragraph with host-app doc (one cross-link). |
| `packages/better_auth-passkey/README.md` | **Modify** — Under **Callback contracts**, add **Ruby vs TypeScript types** (cannot expose TS structs; `verification` uses Ruby/WebAuthn objects). |
| `packages/better_auth-redis-storage/README.md` | **Modify** — One short warning callout when `key_prefix` is empty string (collision surface). |
| `packages/better_auth-mongo-adapter/README.md` | **Modify** — Paragraph on replica sets, transactions off-by-default, operational tuning. |
| `.docs/features/scim.md` | **Modify** — New **Operational recommendations** subsection: uniqueness on `(providerId, accountId)` / accounts index guidance (not schema-enforced in gem). |
| `packages/better_auth-sso/README.md` | **Modify** — Single **Scope / non-goals** blurb pointing to backlog for mTLS, SAML depth, etc. |
| `.docs/backlog/upstream-product-alignment.md` | **Create** — Grouped bullets for SSO, SCIM, Redis, Passkey, Sinatra/router, multi-db stories — **no implementation commitments**. |

---

### Task 1: Host app responsibilities (repo-level)

**Files:**
- Create: `.docs/features/host-app-responsibilities.md`

- [x] **Step 1: Create the file** with sections:

  1. **Origin validation vs browser CORS** — Better Auth uses `trusted_origins` for origin checks where configured; **browser CORS** (`Access-Control-*`) requires explicit Rack middleware or proxy rules in the host application.
  2. **CSRF** — Framework adapters do not replace SameSite cookies or framework CSRF for non-API browser flows; Sinatra apps mount Rack as documented per adapter.
  3. **`trusted_origins` deployment** — Empty or unset lists interact with core normalization and environment-driven defaults; treating `[]` as “reject every browser origin” is a **deployment contract**: document explicit origins per environment rather than assuming gem-only behavior.

  Link from §3 to `packages/better_auth/README.md` once Task 2 adds the anchor paragraph.

- [ ] **Step 2: Commit**

```bash
git add .docs/features/host-app-responsibilities.md
git commit -m "docs: add host-app responsibilities for CORS and origins"
```

---

### Task 2: Core README — `trusted_origins` pointer

**Files:**
- Modify: `packages/better_auth/README.md` (section near configuration / security)

- [x] **Step 1: Add 4–6 sentences** explaining that `trusted_origins` normalization may incorporate defaults from environment and dynamic configuration; an explicit empty array does **not** automatically implement “deny all origins” unless combined with the documented merge rules — refer readers to `.docs/features/host-app-responsibilities.md`.

- [ ] **Step 2: Commit**

```bash
git add packages/better_auth/README.md
git commit -m "docs(core): clarify trusted_origins merge vs strict empty list"
```

---

### Task 3: Hanami + Rails README cross-links

**Files:**
- Modify: `packages/better_auth-hanami/README.md`
- Modify: `packages/better_auth-rails/README.md`

- [x] **Step 1: Hanami** — Add **Mounting and security** (or similar) with: (a) do not apply untested Rails-style `MountedApp` rewrites; (b) be careful with relation/inflector overrides; (c) set `trusted_origins` from app settings with real URLs; (d) link `.docs/features/host-app-responsibilities.md`.

- [x] **Step 2: Rails** — In the existing `trusted_origins` / initializer area, add one sentence + link to the same host-app doc (avoid duplicating the full CORS story).

- [ ] **Step 3: Commit** (one or two commits as you prefer)

```bash
git add packages/better_auth-hanami/README.md packages/better_auth-rails/README.md
git commit -m "docs(hanami,rails): link host-app origin and mounting guidance"
```

---

### Task 4: Sinatra adapter — mount scope and limitations

**Files:**
- Modify: `packages/better_auth-sinatra/README.md`

- [x] **Step 1: Add “Mounting and Rack path”** — When the app is mounted under a sub-path, `SCRIPT_NAME` and prefix behavior depend on the Rack server and mount stack; the adapter does not globally normalize paths — verify redirects and cookie paths in integration tests.

- [x] **Step 2: Add “Helpers scope”** — Current helpers focus on session/cookie authentication for documented routes; attaching Bearer/JWT validation to arbitrary routes may require application-level middleware or future router/session work — not promised by `require_authentication` alone.

- [x] **Step 3: Add “Migrations” one-liner** — SQL helpers split statements conservatively; exotic procedural SQL may need manual migration edits.

- [ ] **Step 4: Commit**

```bash
git add packages/better_auth-sinatra/README.md
git commit -m "docs(sinatra): mounting paths, helper scope, migration constraints"
```

---

### Task 5: Passkey README — callback types

**Files:**
- Modify: `packages/better_auth-passkey/README.md`

- [x] **Step 1: Under “Callback contracts”, add subsection “Ruby vs TypeScript callback shapes”** — State explicitly that `verification` and related objects are **Ruby** (`WebAuthn` gem types and hashes), not TypeScript interfaces from `@better-auth/passkey`; parity is behavioral (wire JSON), not static type export. One short example: refer to `data[:verification]` as Ruby object, not a SimpleWebAuthn DTO.

- [ ] **Step 2: Commit**

```bash
git add packages/better_auth-passkey/README.md
git commit -m "docs(passkey): clarify Ruby callback types vs upstream TS"
```

---

### Task 6: Redis storage — empty `key_prefix`

**Files:**
- Modify: `packages/better_auth-redis-storage/README.md`

- [x] **Step 1:** After the existing `key_prefix` paragraph (already stating empty string is honored verbatim), add a **Warning** block: empty prefix puts keys at the root of the Redis logical namespace — collisions across apps or tenants are possible; prefer explicit prefixes for shared Redis.

- [ ] **Step 2: Commit**

```bash
git add packages/better_auth-redis-storage/README.md
git commit -m "docs(redis-storage): warn on empty key_prefix collision risk"
```

---

### Task 7: Mongo adapter — operations paragraph

**Files:**
- Modify: `packages/better_auth-mongo-adapter/README.md`

- [x] **Step 1:** Expand **Notes** with a short **Transactions** bullet: multi-document transactions may be unavailable on standalone deployments or require replica sets; the example uses `transaction: false`; enable transactions only when the deployment and driver settings support them.

- [ ] **Step 2: Commit**

```bash
git add packages/better_auth-mongo-adapter/README.md
git commit -m "docs(mongo-adapter): document transaction and deployment limits"
```

---

### Task 8: SCIM feature note — operational index

**Files:**
- Modify: `.docs/features/scim.md`

- [x] **Step 1: Add “Operational database recommendations”** — Recommend a **unique** constraint or application-level invariant on account identity used for IdP mapping (e.g. scope by `providerId` and external account id) to avoid duplicate provider links; note that concrete DDL belongs in the app’s migration for its SQL/Mongo adapter, not inside the SCIM gem.

- [ ] **Step 2: Commit**

```bash
git add .docs/features/scim.md
git commit -m "docs(scim): operational uniqueness recommendations"
```

---

### Task 9: SSO gem — scope blurb

**Files:**
- Modify: `packages/better_auth-sso/README.md`

- [x] **Step 1: Add “Scope and non-goals (this release)”** — One short list: advanced enterprise features (e.g. `private_key_jwt`, mTLS, deep SAML edge cases) and large refactors are tracked in the product alignment backlog, not implied by the current gem surface.

- [x] **Step 2: Link** to `.docs/backlog/upstream-product-alignment.md` (after Task 10 creates it). If Task 9 runs before Task 10, add the link in a follow-up commit with Task 10.

- [ ] **Step 3: Commit**

```bash
git add packages/better_auth-sso/README.md
git commit -m "docs(sso): point non-goals to alignment backlog"
```

---

### Task 10: Product / upstream alignment backlog (grouped)

**Files:**
- Create: `.docs/backlog/upstream-product-alignment.md`

- [x] **Step 0: Ensure directory exists**

```bash
mkdir -p /Users/sebastiansala/projects/better-auth/.docs/backlog
```

- [x] **Step 1: Create the file** with top matter explaining this is **not a commitment** — ideas that need product decision, upstream coordination, or major effort. Group by **SSO**, **SCIM**, **Passkey/WebAuthn**, **Redis storage**, **Routing / Sinatra / multi-db**, **Core** (e.g. `debugLogs` API, `OptionBuilder` strictness, PK DDL portability). Each bullet: one line title + one line “why deferred”.

  Example entries to include (condense from the exclusion tables the user provided):

  - SSO: `private_key_jwt`, mTLS, lazy `ruby-saml` load, `disable_implicit_sign_up` parity, SLO/XML depth.
  - SCIM: RFC list pagination, Group/Bulk, `delete_user` vs unlink semantics.
  - Passkey: optional UV policy change, attestation beyond `none`, 401/400 policy for verify errors, `deviceType` string parity.
  - Redis: dedicated error taxonomy, cluster test matrix, sub-second TTL parity.
  - Sinatra / core: Session-level Bearer for arbitrary routes, shared `MountedApp` extraction in core, strict `OptionBuilder`.
  - Core: `debugLogs` parity, database sharding, UUID PK migration strategy, global negative-path QA policy.

- [ ] **Step 2: Commit**

```bash
git add .docs/backlog/upstream-product-alignment.md
git commit -m "docs: add upstream and product alignment backlog"
```

- [x] **Step 3: If Task 9 already committed without link**, amend or add a small commit adding the link from `better_auth-sso` README to this file.

---

### Task 11: Optional index in `.docs/README.md`

**Files:**
- Modify: `.docs/README.md`

- [x] **Step 1: Under Structure**, add a line for `backlog/` describing `upstream-product-alignment.md` as a parking lot for cross-cutting ideas.

- [ ] **Step 2: Commit**

```bash
git add .docs/README.md
git commit -m "docs: index product alignment backlog"
```

---

## Self-review

1. **Coverage:** Every “document instead of code” item from the user’s lists is either a concrete Task (1–9, 11) or folded into the backlog file (Task 10).
2. **Placeholders:** No TBD implementation steps; markdown-only.
3. **No duplicate api-key plan:** API key code changes remain in `2026-05-03-1515--api-key-hardening-plan.md`.

---

**Plan saved to `.docs/plans/2026-05-03-1700--cross-cutting-docs-and-alignment-backlog.md`.**

**Execution options:**

1. **Subagent-driven (recommended)** — one subagent per task cluster (Tasks 1–2 together, 3–4, …); skill: **superpowers:subagent-driven-development**.
2. **Inline execution** — sequential edits in one session; skill: **superpowers:executing-plans**.

**Which approach?**
