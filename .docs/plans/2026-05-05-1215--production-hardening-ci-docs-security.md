# Implementation plan: pre-production CI hardening, docs, and security

> **For agentic workers:** Recommended SUB-SKILL: `superpowers:subagent-driven-development` or `superpowers:executing-plans`. Steps use checkbox syntax (`- [ ]`) for tracking.

**Goal:** Close operational gaps between local `rake ci` and GitHub CI, widen CI triggers, align public docs with the parity matrix, and reduce security risk in Stripe webhooks, OAuth client secret (custom hash), API keys in session, and SCIM.

**Architecture:** File-scoped changes (workflows, `Rakefile`, affected gems). No monorepo redesign. Where a default change would be breaking (SCIM), prefer documentation + an explicit opt-in before breaking existing installs without a guide.

**Tech stack:** Ruby 3.4.x, GitHub Actions, Minitest / RSpec per package, StandardRB.

---

## What it means to include `.ruby-version` (and optionally `docs/**`) in `paths` in `ci.yml`

GitHub Actions can filter when a workflow runs using `on.pull_request.paths` and `on.push.paths`. **The workflow is only scheduled if some file in the PR matches the list**; otherwise, **the PR can be merged without running tests** (unless branch rules require another check).

**What happens if you do NOT include certain paths:**

- You only change `.ruby-version` at the repo root (Ruby version bump): **no current path matches** (`packages/**` unchanged) → **CI does not run** → apparently “green” merges without validating that all 12 packages still pass tests on the new Ruby.
- You only change public docs under `docs/**` or internal notes under `.docs/**`: likewise, **CI may not trigger** → broken snippets or links not caught by automation (lower risk than code, but still a gap).

**“Include `.ruby-version`”** = add an explicit `'**/.ruby-version'` or `'.ruby-version'` entry under `paths` for both `pull_request` and `push`, so **any Ruby bump re-runs full CI**.

**“Include `docs/**` (and optional `.docs/**`)”** = the same idea for docs-only PRs if you want to **enforce doc builds or linters** (once you add a docs-site job).

**Alternative (“touch `packages/**` anyway”)** = on PRs that only bump Ruby, make a cosmetic or comment-only change somewhere under `packages/**` purely to **force** a match on `packages/**`. It works but is hacky and easy to forget; **widening `paths` is preferable**.

---

## File map

| Area | Create | Modify |
|------|--------|--------|
| CI triggers | — | `.github/workflows/ci.yml` |
| Local parity vs CI | — | `Rakefile` (tasks `:ci`, `:lint`, `:lint:fix`, `STANDARD_PATHS`, optional `:install`) |
| Stripe webhook | — | `packages/better_auth-stripe/lib/better_auth/stripe/routes/stripe_webhook.rb`, tests under `packages/better_auth-stripe/test/...` |
| OAuth secret hash callback | — | `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`, tests under `packages/better_auth/test/...` |
| API key + session | — | `packages/better_auth-api-key/lib/better_auth/api_key/session.rb` and/or docs; tests |
| SCIM defaults | — | `packages/better_auth-scim/lib/better_auth/plugins/scim.rb`, README, changelog |
| Docs / contradictions | — | `docs/content/docs/supported-features.mdx`, `docs/content/docs/introduction.mdx` (others if needed) |
| Optional supply chain | — | new job in `.github/workflows/ci.yml` or separate workflow |

---

## Findings inventory → effect and priority

| # | Finding | Why it matters | Effect if fixed | Risk / note |
|---|---------|----------------|-----------------|-------------|
| 1 | CI `paths` omits `.ruby-version`, `docs/**`, `.docs/**` | Docs-only or Ruby-only PR may skip CI | Fewer blind merges; confidence in Ruby bumps | More CI runs (usually negligible cost) |
| 2 | Root `rake ci` skips oauth-provider, scim, sso + lint for those three | Local “green”, GitHub red | Local dev ≈ GH for all 12 packages | Larger `Rakefile` + longer local runs |
| 3 | Redis: CI runs `test:integration`, root rake does not | Failures only on GH or with manual Redis | Catch real-Redis failures earlier | Requires `REDIS_URL` / local service or documented skip |
| 4 | Stripe: if `stripe_client` has no `#webhooks`, raw `payload` is used without signature verification | Forged webhooks if client is customized wrong | Stripe-like integrity restored | May break installs that relied on bypass (document BREAKING) |
| 5 | Stripe: broad `rescue` hides failures | Hard to separate bug vs attack vs misconfig | Clearer logs/errors | Watch PII in error messages |
| 6 | OAuth `store_client_secret` hash mode uses `==` | Non-constant-time compare for custom hash | Hardening for tenants with custom hash | Same behavior except timing |
| 7 | API key stored in `session["token"]` | Leak if session store/logs expose values | Smaller secret surface | May break code that reads raw key from session |
| 8 | SCIM `store_scim_token: "plain"` by default | Long-lived secrets in plaintext in DB | Smaller blast radius on DB leak | Changing default is breaking without migration |
| 9 | Docs: Dub / OpenAPI / intro vs matrix | Confusing adoption, wrong expectations | Message aligned with `upstream-parity-matrix` | Editorial only |
| 10 | `release.yml` tied to check name `"ci"` | Renaming job breaks publishing | Document or parameterize | Touch release carefully |

---

### Task 1: Expand `paths` in CI

**Files:**

- Modify: `.github/workflows/ci.yml` (`on.pull_request.paths` and `on.push.paths` blocks, ~lines 9–26)

**YAML to append** (below existing entries):

```yaml
      - '.ruby-version'
      - '**/\.ruby-version'
      - 'docs/**'
      - '.docs/**'
```

**Note:** In GitHub’s path filter, a glob for all `.ruby-version` files is usually `**/.ruby-version` (no backslash escape). If your IDE linter complains, use only:

```yaml
      - '.ruby-version'
      - '.docs/**'
      - 'docs/**'
```

and rely on package copies under `packages/**` when you bump versions in bulk — **then bumps that only edit `packages/better_auth-foo/.ruby-version` still match `packages/**`**. The main gap is **root-only `/.ruby-version`**: that is why the root `'.ruby-version'` line is the critical one.

- [ ] **Step 1:** Add `'.ruby-version'`, `'docs/**'`, `'.docs/**'` to both `paths` arrays.
- [ ] **Step 2:** Open a test PR that only touches root `.ruby-version` and confirm on the Checks tab that **`ci`** is scheduled.
- [ ] **Step 3:** Conventional commit, e.g. `ci: expand workflow path filters for ruby version and docs`.

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run workflow on ruby-version and docs path changes"
```

---

### Task 2: Align root `Rakefile` with all 12 packages (tests + STANDARD_PATHS)

**Files:**

- Modify: `Rakefile` (`STANDARD_PATHS`, `task :ci`, and mirror into `:lint` / `:lint:fix` / `:clean` if applicable)

**Add to `STANDARD_PATHS`** analogous entries for:

- `packages/better_auth-oauth-provider/{Rakefile,lib,test}`
- `packages/better_auth-scim/{Rakefile,lib,test}`
- `packages/better_auth-sso/{Rakefile,lib,test}`

**In `task :ci`**, after `better_auth-stripe` (or a consistent alphabetical order), invoke:

```ruby
  puts "\n🧪 Running tests in packages/better_auth-oauth-provider..."
  cd "packages/better_auth-oauth-provider" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake test"
  end

  puts "\n🧪 Running tests in packages/better_auth-scim..."
  cd "packages/better_auth-scim" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake test"
  end

  puts "\n🧪 Running tests in packages/better_auth-sso..."
  cd "packages/better_auth-sso" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake test"
  end
```

**Rationale:** Same test coverage as GH for those three gems; workspace `standardrb` will format them too.

- [ ] **Step 1:** Edit `STANDARD_PATHS` and `:ci`.
- [ ] **Step 2:** Run from repo root:

```bash
cd /Users/sebastiansala/projects/better-auth && bundle exec rake ci
```

**Expected:** Completes without errors (may take longer). If Postgres/MySQL/Redis/Mongo are not available locally, some packages may still fail—optionally document in root README.

- [ ] **Step 3:** Replicate new paths in `task :lint` and `task "lint:fix"` (same `cd` blocks as `:ci`, or extract a helper later for DRY).
- [ ] **Step 4:** Commit `build: extend workspace rake ci to oauth-provider scim sso`.

---

### Task 3 (optional): Redis integration from root rake

**Files:**

- Modify: `Rakefile` — in the `better_auth-redis-storage` block, after `bundle exec rake`, if `ENV["REDIS_URL"]` or `ENV["RUN_REDIS_INTEGRATION"] == "1"`:

```ruby
sh "REDIS_INTEGRATION=1 BUNDLE_GEMFILE=Gemfile bundle exec rake test:integration"
```

- [ ] **Step 1:** Implement the conditional with a short explanatory comment.
- [ ] **Step 2:** With `docker run -p 6379:6379 redis:7-alpine`, run `REDIS_URL=redis://localhost:6379/0 bundle exec rake ci` and confirm integration runs.
- [ ] **Step 3:** Commit `build: optionally run redis integration tests from workspace rake`.

---

### Task 4: Stripe webhook — require signature verification

**Files:**

- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/routes/stripe_webhook.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/stripe/routes/stripe_webhook_test.rb`

**Desired behavior:** If `stripe_client(config)` does not expose `webhooks` with `construct_event`, **do not** accept raw `payload`: raise `APIError` with a clear code (new `ERROR_CODES` entry if needed).

**Example new test (Minitest)** — adjust package helpers if they exist:

```ruby
def test_rejects_payload_when_client_has_no_webhooks
  config = {
    stripe_webhook_secret: "whsec_test",
    # Force a fake client without #webhooks using the same mechanism as other plugin tests
  }
  # Simulate POST with body and stripe-signature header (invalid or valid);
  # key assertion: without construct_event, response must be an error, not success.
end
```

(Real implementation should reuse mocks from `better_auth-stripe/test/better_auth/plugins/stripe_test.rb` if those stub `stripe_client`.)

- [ ] **Step 1:** Write a test that would pass today with bypass and must fail first.
- [ ] **Step 2:** Run `cd packages/better_auth-stripe && bundle exec rake test` — expect FAIL.
- [ ] **Step 3:** Replace `else payload` branch with explicit error.
- [ ] **Step 4:** Add missing/malformed signature cases using expected `Stripe::StripeError` if tests use real client — follow existing patterns.
- [ ] **Step 5:** `bundle exec standardrb`, `bundle exec rake test`.
- [ ] **Step 6:** Document BREAKING in `packages/better_auth-stripe/CHANGELOG.md` if any installs lack `#webhooks`.
- [ ] **Step 7:** Commit `fix(stripe): require webhook signature verification path`.

---

### Task 5: OAuth Protocol — constant-time compare for `mode[:hash]`

**Files:**

- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb` (`verify_client_secret` method, ~line 866)
- Create or extend tests near existing OAuth protocol tests (`packages/better_auth/test/better_auth/plugins/oauth_protocol_test.rb` or equivalent after grep).

**Proposed code** (replace the `return mode[:hash]... ==` line):

```ruby
digested = mode[:hash].call(provided_secret).to_s
return Crypto.constant_time_compare(digested, stored_secret.to_s)
```

- [ ] **Step 1:** Find tests covering `store_client_secret` Hash mode; if missing, add a minimal test with `mode: {hash: proc { |s| Digest::SHA256.hexdigest(s) }}`.
- [ ] **Step 2:** Implement the change.
- [ ] **Step 3:** `cd packages/better_auth && bundle exec rake test`
- [ ] **Step 4:** Commit `fix(oauth): use constant-time compare for custom hashed client secrets`.

---

### Task 6: API Key — revisit token persistence in session

**Files:**

- Read upstream equivalent if present (`upstream/...`).
- Modify per decision: `packages/better_auth-api-key/lib/better_auth/api_key/session.rb`

**Options (pick one at implementation time):**

- **A (conservative):** Do not change session shape; document in `docs/content/docs/plugins/api-key.mdx` and README that **`session["token"]` holds the raw key** and the backing store must be safe (no large signed cookies, no logging).
- **B:** Store only `record["id"]` or an irreversible fingerprint like `tokenFingerprint` if upstream routing only needs correlation — **only** if every code path reading session works without the raw key.

- [ ] **Step 1:** Compare with upstream TS for an informed decision.
- [ ] **Step 2:** Implement chosen option + regression tests under `packages/better_auth-api-key/test/`.
- [ ] **Step 3:** CHANGELOG entry if user-visible behavior changes.

---

### Task 7: SCIM — token storage default

**Files:**

- `packages/better_auth-scim/lib/better_auth/plugins/scim.rb`
- `packages/better_auth-scim/README.md`

**Recommended option (avoid silent breakage):** Keep `"plain"` default but **warn** once at init when `ENV["RACK_ENV"] == "production"` and `store_scim_token == "plain"`, or document prominently “you SHOULD use hash/encrypt per adapters”.

**Radical option:** change default to `:hashed` or similar with a described migration → **semver minor** + upgrade guide.

- [ ] **Step 1:** Explicit decision in PR description.
- [ ] **Step 2:** Implement warnings or default change + changelog.
- [ ] **Step 3:** Tests covering the new branch if applicable.

---

### Task 8: Docs — align public messaging with the matrix

**Files:**

- `docs/content/docs/supported-features.mdx` — fix **Dub** row/feature to reflect the plugin lives at `packages/better_auth/lib/better_auth/plugins/dub.rb` (or mark partial with known gaps).
- Tweak **OpenAPI** card to separate “generator supported” vs “upstream OpenAPI snapshot parity”.
- `docs/content/docs/introduction.mdx` — align tone with SSO/Stripe/OpenAPI rows given current truth in `.docs/features/upstream-parity-matrix.md`.

- [ ] **Step 1:** Edit up to three files in one editorial PR.
- [ ] **Step 2:** Human proofread via `git diff docs/`.
- [ ] **Step 3:** Commit `docs: align supported-features and introduction with parity matrix`.

---

### Task 9 (optional backlog): Supply chain + pinned images

**Files:**

- `.github/workflows/ci.yml`

- [ ] Add a `bundle-audit` job on every PR (needs `bundler-audit` or script).
- [ ] Pin `postgres`, `mysql`, `mongo`, `redis` images to digest SHAs instead of `:latest`.

---

### Task 10 (optional): Document release coupling to check name `"ci"`

**Files:**

- `.github/workflows/release.yml` (YAML comment above `verify-ci` step) or `CONTRIBUTING.md`

- [ ] Explicit text: “If you rename the aggregate `ci` job in `ci.yml`, update the lookup in `release.yml`."

---

## Self-review (internal checklist satisfied)

- [x] Each prior audit finding maps to a task or is marked backlog/optional.
- [x] No “TBD” in executable steps — only labeled forks (SCIM radical vs warns; API key A vs B).
- [x] Types/code paths consistent with this Ruby repo.

---

Saved at `.docs/plans/2026-05-05-1215--production-hardening-ci-docs-security.md`.

**Suggested execution order:** (1) **Subagent-driven** — one agent per task with review between tasks; (2) **Inline** — run Tasks 1–2 and 8 first (fast), then 4–5 (security), then 6–7 (design).

Which execution approach do you want?
