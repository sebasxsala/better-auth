# Core vs Upstream Parity Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a verified parity map between `packages/better_auth` and upstream (`upstream/packages/better-auth` + `upstream/packages/core`), then close the highest-risk behavior/test gaps with TDD.

**Architecture:** First, create auditable artifacts (module map + behavior matrix + missing-test backlog) from source and test diffs. Then implement parity fixes in priority order (session refresh contract, sign-up/sign-in edge behavior, organization route matrix, OAuth2 validation), always porting upstream test intent into Minitest before code changes.

**Tech Stack:** Ruby (Minitest, StandardRB), TypeScript upstream reference tests (Vitest), ripgrep, Markdown audit docs.

---

## File Structure (planned changes)

- Create: `docs/superpowers/reports/2026-04-29-core-upstream-module-map.md` (module and boundary mapping)
- Create: `docs/superpowers/reports/2026-04-29-core-upstream-behavior-gaps.md` (behavior + test parity matrix)
- Create: `packages/better_auth/test/better_auth/routes/session_refresh_parity_test.rb` (session refresh parity tests)
- Create: `packages/better_auth/test/better_auth/routes/trusted_origins_parity_test.rb` (origin policy parity tests)
- Modify: `packages/better_auth/lib/better_auth/routes/session.rb` (refresh/defer semantics)
- Modify: `packages/better_auth/lib/better_auth/routes/sign_in.rb` (origin/csrf matrix parity)
- Modify: `packages/better_auth/lib/better_auth/routes/sign_up.rb` (rollback/enumeration parity)
- Modify: `packages/better_auth/test/better_auth/routes/sign_in_test.rb` (expanded upstream-equivalent assertions)
- Modify: `packages/better_auth/test/better_auth/routes/sign_up_test.rb` (rollback and indistinguishability assertions)
- Modify: `packages/better_auth/test/better_auth/plugins/organization_test.rb` (route-level access-control matrix)
- Create: `packages/better_auth/test/better_auth/plugins/oauth2_core_parity_test.rb` (validate-token/issuer edge cases)
- Create (optional if extraction gate passes): `packages/better_auth/lib/better_auth/internal/adapter_support.rb` (shared internal support module)
- Create: `docs/superpowers/reports/2026-04-29-core-extraction-decision.md` (extract-now vs wait decision with thresholds)

### Task 1: Baseline parity inventory from upstream and Ruby

**Files:**
- Create: `docs/superpowers/reports/2026-04-29-core-upstream-module-map.md`
- Create: `docs/superpowers/reports/2026-04-29-core-upstream-behavior-gaps.md`
- Test: `packages/better_auth/test/better_auth_test.rb` (smoke reference only; no behavior change in this task)

- [ ] **Step 1: Write the failing test (audit guard)**

```ruby
# packages/better_auth/test/parity/audit_artifacts_test.rb
# frozen_string_literal: true

require "test_helper"

class AuditArtifactsTest < Minitest::Test
  def test_audit_reports_exist
    assert File.exist?(File.expand_path("../../docs/superpowers/reports/2026-04-29-core-upstream-module-map.md", __dir__))
    assert File.exist?(File.expand_path("../../docs/superpowers/reports/2026-04-29-core-upstream-behavior-gaps.md", __dir__))
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/parity/audit_artifacts_test.rb`  
Expected: FAIL with missing report files.

- [ ] **Step 3: Write minimal implementation (initial reports)**

```md
# docs/superpowers/reports/2026-04-29-core-upstream-module-map.md
- upstream/packages/core/src/context -> packages/better_auth/lib/better_auth/context.rb
- upstream/packages/core/src/oauth2 -> packages/better_auth/lib/better_auth/plugins/generic_oauth.rb
- upstream/packages/better-auth/src/api/routes/session-api.test.ts -> packages/better_auth/lib/better_auth/routes/session.rb
```

```md
# docs/superpowers/reports/2026-04-29-core-upstream-behavior-gaps.md
## Missing high-risk tests
1. deferSessionRefresh contract
2. sign-up rollback on session-creation failure
3. sign-in trusted origin matrix
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/parity/audit_artifacts_test.rb`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/reports/2026-04-29-core-upstream-module-map.md docs/superpowers/reports/2026-04-29-core-upstream-behavior-gaps.md packages/better_auth/test/parity/audit_artifacts_test.rb
git commit -m "test: add parity audit artifact guardrails"
```

### Task 2: Port session refresh contract from upstream tests

**Files:**
- Create: `packages/better_auth/test/better_auth/routes/session_refresh_parity_test.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/session.rb`
- Test: `packages/better_auth/test/better_auth/routes/session_routes_test.rb`

- [ ] **Step 1: Write the failing test**

```ruby
def test_get_session_marks_needs_refresh_when_defer_session_refresh_enabled
  auth = build_auth(session: {expires_in: 1, update_age: 0}, advanced: {defer_session_refresh: true})
  response = call_auth(auth, "GET", "/api/auth/get-session", headers: auth_headers)
  assert_equal 200, response.status
  assert_equal true, json_body(response)["needsRefresh"]
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/routes/session_refresh_parity_test.rb`  
Expected: FAIL because `needsRefresh` is missing or always false.

- [ ] **Step 3: Write minimal implementation**

```ruby
# inside get-session handler
if advanced.defer_session_refresh
  body["needsRefresh"] = session_needs_refresh?(session)
  return json(body)
end

refresh_session_if_needed!(session)
json(body)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/routes/session_refresh_parity_test.rb test/better_auth/routes/session_routes_test.rb`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth/lib/better_auth/routes/session.rb packages/better_auth/test/better_auth/routes/session_refresh_parity_test.rb packages/better_auth/test/better_auth/routes/session_routes_test.rb
git commit -m "test: port session refresh defer semantics from upstream"
```

### Task 3: Close sign-up parity gaps (rollback + enumeration indistinguishability)

**Files:**
- Modify: `packages/better_auth/test/better_auth/routes/sign_up_test.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/sign_up.rb`
- Test: `upstream/packages/better-auth/src/api/routes/sign-up.test.ts` (reference behavior)

- [ ] **Step 1: Write the failing tests**

```ruby
def test_sign_up_rolls_back_user_when_session_creation_fails
  force_session_creation_failure!
  response = post_json("/api/auth/sign-up", valid_sign_up_payload)
  assert_equal 500, response.status
  assert_nil find_user_by_email(valid_sign_up_payload[:email])
end

def test_duplicate_email_response_is_indistinguishable_when_prevent_enumeration_enabled
  existing = create_user(email: "dup@example.com")
  response = post_json("/api/auth/sign-up", payload(email: existing.email), config: {email_and_password: {prevent_account_creation_enumeration: true}})
  assert_equal 200, response.status
  assert_equal %w[token user], json_body(response).keys.sort
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/routes/sign_up_test.rb`  
Expected: FAIL on rollback and response-shape assertions.

- [ ] **Step 3: Write minimal implementation**

```ruby
adapter.transaction do
  user = create_user!(payload)
  session = create_session!(user)
  return success_payload(user, session)
end

rescue SessionCreateError
  # transaction rollback preserves no partial user
  error_response("SESSION_CREATE_FAILED")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/routes/sign_up_test.rb`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth/lib/better_auth/routes/sign_up.rb packages/better_auth/test/better_auth/routes/sign_up_test.rb
git commit -m "fix: align sign-up rollback and enumeration behavior with upstream"
```

### Task 4: Expand sign-in trusted-origin and CSRF matrix

**Files:**
- Modify: `packages/better_auth/test/better_auth/routes/sign_in_test.rb`
- Create: `packages/better_auth/test/better_auth/routes/trusted_origins_parity_test.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/sign_in.rb`

- [ ] **Step 1: Write the failing tests**

```ruby
def test_sign_in_allows_same_origin_without_csrf_cookie
  response = post_sign_in(origin: "https://app.example.com", host: "app.example.com", csrf_cookie: nil)
  assert_equal 200, response.status
end

def test_sign_in_blocks_cross_site_without_csrf_cookie
  response = post_sign_in(origin: "https://evil.example", host: "app.example.com", csrf_cookie: nil)
  assert_equal 403, response.status
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/routes/sign_in_test.rb test/better_auth/routes/trusted_origins_parity_test.rb`  
Expected: FAIL on at least one same-origin/same-site branch.

- [ ] **Step 3: Write minimal implementation**

```ruby
origin_state = origin_policy.evaluate(request_origin:, request_host:, csrf_cookie_present:)
return forbidden_origin unless origin_state.allowed?

authenticate_with_password!
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/routes/sign_in_test.rb test/better_auth/routes/trusted_origins_parity_test.rb`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth/lib/better_auth/routes/sign_in.rb packages/better_auth/test/better_auth/routes/sign_in_test.rb packages/better_auth/test/better_auth/routes/trusted_origins_parity_test.rb
git commit -m "test: port sign-in origin policy matrix from upstream"
```

### Task 5: Strengthen organization route-level permission/error matrix

**Files:**
- Modify: `packages/better_auth/test/better_auth/plugins/organization_test.rb`
- Test reference: `upstream/packages/better-auth/src/plugins/organization/routes/crud-org.test.ts`
- Test reference: `upstream/packages/better-auth/src/plugins/organization/routes/crud-members.test.ts`
- Test reference: `upstream/packages/better-auth/src/plugins/organization/routes/crud-access-control.test.ts`

- [ ] **Step 1: Write failing tests for forbidden/not-found/code matrix**

```ruby
def test_update_org_requires_owner_role
  response = patch_json("/api/auth/organization/update", as_member_session, payload: {organization_id: org.id, name: "new"})
  assert_equal 403, response.status
  assert_equal "FORBIDDEN", json_body(response)["code"]
end

def test_delete_member_returns_not_found_for_unknown_member
  response = delete_json("/api/auth/organization/member", owner_session, payload: {member_id: "missing"})
  assert_equal 404, response.status
  assert_equal "NOT_FOUND", json_body(response)["code"]
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/plugins/organization_test.rb`  
Expected: FAIL on status/code parity.

- [ ] **Step 3: Write minimal implementation (only if tests expose real behavior drift)**

```ruby
return error("FORBIDDEN", status: 403) unless policy.can_manage_organization?(actor, organization)
return error("NOT_FOUND", status: 404) unless member
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/plugins/organization_test.rb`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth/test/better_auth/plugins/organization_test.rb packages/better_auth/lib/better_auth/plugins/organization.rb
git commit -m "test: align organization route error matrix with upstream"
```

### Task 6: Add OAuth2 core parity tests (issuer/token validation edges)

**Files:**
- Create: `packages/better_auth/test/better_auth/plugins/oauth2_core_parity_test.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/generic_oauth.rb`
- Test reference: `upstream/packages/core/src/oauth2/validate-token.test.ts`

- [ ] **Step 1: Write failing tests for issuer-required and issuer-mismatch**

```ruby
def test_validate_token_fails_when_required_issuer_missing
  error = assert_raises(BetterAuth::OAuth2::ValidationError) do
    validate_token(id_token_without_issuer, required_issuer: "https://issuer.example")
  end
  assert_match "issuer", error.message
end

def test_validate_token_fails_on_issuer_mismatch
  error = assert_raises(BetterAuth::OAuth2::ValidationError) do
    validate_token(id_token_with_issuer("https://a"), required_issuer: "https://b")
  end
  assert_match "issuer mismatch", error.message
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/plugins/oauth2_core_parity_test.rb`  
Expected: FAIL for missing validation branches.

- [ ] **Step 3: Write minimal implementation**

```ruby
issuer = claims["iss"]
raise ValidationError, "issuer missing" if required_issuer && issuer.nil?
raise ValidationError, "issuer mismatch" if required_issuer && issuer != required_issuer
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/plugins/oauth2_core_parity_test.rb test/better_auth/plugins/generic_oauth_test.rb`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth/lib/better_auth/plugins/generic_oauth.rb packages/better_auth/test/better_auth/plugins/oauth2_core_parity_test.rb packages/better_auth/test/better_auth/plugins/generic_oauth_test.rb
git commit -m "test: add oauth2 issuer validation parity with upstream core"
```

### Task 7: Decide extraction of internal core/support module (not new gem yet)

**Files:**
- Create: `docs/superpowers/reports/2026-04-29-core-extraction-decision.md`
- Optional Create: `packages/better_auth/lib/better_auth/internal/adapter_support.rb`
- Optional Modify: `packages/better_auth-rails/lib/better_auth/rails.rb`
- Optional Modify: `packages/better_auth-sinatra/lib/better_auth/sinatra.rb`

- [ ] **Step 1: Write failing decision guard test**

```ruby
# packages/better_auth/test/parity/extraction_decision_test.rb
def test_extraction_decision_report_exists
  assert File.exist?(File.expand_path("../../docs/superpowers/reports/2026-04-29-core-extraction-decision.md", __dir__))
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/parity/extraction_decision_test.rb`  
Expected: FAIL because report file does not exist.

- [ ] **Step 3: Write minimal implementation (decision report)**

```md
# docs/superpowers/reports/2026-04-29-core-extraction-decision.md
Decision: Do not create a new gem now.
Triggers to revisit: 3+ adapters sharing >200 LOC duplicated helpers, repeated cross-adapter fixes for 2 releases.
Interim: keep extraction internal (`BetterAuth::Internal::AdapterSupport`) only when concrete duplication is removed by tests.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/parity/extraction_decision_test.rb`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/reports/2026-04-29-core-extraction-decision.md packages/better_auth/test/parity/extraction_decision_test.rb
git commit -m "docs: record core extraction decision and revisit thresholds"
```

### Task 8: Full verification and parity sign-off

**Files:**
- Modify: `docs/superpowers/reports/2026-04-29-core-upstream-behavior-gaps.md` (mark completed gaps)
- Test: `packages/better_auth/test/**/*_test.rb`

- [ ] **Step 1: Write failing sign-off checklist test**

```ruby
def test_behavior_gap_report_marks_top_priority_items_done
  report = File.read(File.expand_path("../../docs/superpowers/reports/2026-04-29-core-upstream-behavior-gaps.md", __dir__))
  assert_includes report, "- [x] deferSessionRefresh contract"
  assert_includes report, "- [x] sign-up rollback and enumeration parity"
  assert_includes report, "- [x] sign-in trusted origin matrix"
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/better_auth && bundle exec ruby -Itest test/parity/signoff_test.rb`  
Expected: FAIL until report is updated.

- [ ] **Step 3: Write minimal implementation**

```md
## Top-risk parity backlog
- [x] deferSessionRefresh contract
- [x] sign-up rollback and enumeration parity
- [x] sign-in trusted origin matrix
- [ ] organization route matrix (remaining edge cases, if any)
- [ ] oauth2 helper parity (remaining edge cases, if any)
```

- [ ] **Step 4: Run full test suite**

Run: `cd packages/better_auth && bundle exec rake ci`  
Expected: PASS (lint + tests).

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/reports/2026-04-29-core-upstream-behavior-gaps.md packages/better_auth/test/parity/signoff_test.rb
git commit -m "chore: finalize upstream parity audit sign-off"
```

## Self-Review

- **Spec coverage:** This plan covers deep comparison against both upstream packages, explicit behavior-difference detection, test parity focus, and a final architecture decision on splitting `core/support`.
- **Placeholder scan:** Removed generic placeholders; each step includes concrete paths, commands, and code examples.
- **Type consistency:** Uses consistent route/test naming (`session_refresh_parity_test`, `trusted_origins_parity_test`, parity report file names) across all tasks.

