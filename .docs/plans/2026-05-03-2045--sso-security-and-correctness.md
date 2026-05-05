# SSO security and correctness hardening

> **For agentic workers:** Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the highest-impact gaps found in the `better_auth-sso` review: fix configuration and API mistakes, harden the OIDC callback and ID token path, make domain TXT verification exact, return SAML SP metadata as real XML, and declare the `jwt` runtime dependency explicitly.

**Architecture:** Changes stay localized to `packages/better_auth-sso/`: the main plugin file `lib/better_auth/plugins/sso.rb` (OIDC state, authorize URL, ID token verification, domain check, SP metadata, SAML config validation), `lib/better_auth/sso/saml_state.rb` (namespaced errors), `better_auth-sso.gemspec` (dependencies), and Minitest files under `test/better_auth/sso/`. No new runtime gems beyond `jwt` (already used; make direct). Note: after review, no plain-text bearer-token comparison exists in the current SSO plugin (unlike SCIM `default_scim`), so `constant_time_compare` is not required here.

**Tech stack:** Ruby 3.2+, Minitest, `better_auth` core, `jwt`, `ruby-saml` (existing).

**Worktree:** Prefer a dedicated git worktree for this plan (see repository `AGENTS.md`).

---

## File map (what changes where)

| File | Role |
|------|------|
| `packages/better_auth-sso/lib/better_auth/plugins/sso.rb` | OIDC: `nonce` in state + auth URL; bind `state["providerId"]` to path; extend `sso_validate_oidc_id_token`; domain TXT equality; SAML URL validation copy and `single_logout_service` check; SP metadata return path |
| `packages/better_auth-sso/lib/better_auth/sso/saml_state.rb` | Replace bare `APIError` with `BetterAuth::APIError` |
| `packages/better_auth-sso/better_auth-sso.gemspec` | Add `spec.add_dependency "jwt", ...` aligned with `packages/better_auth/better_auth.gemspec` |
| `packages/better_auth-sso/CHANGELOG.md` | User-visible: typo fix, new OIDC errors, domain verification behavior, `jwt` direct dep |
| `packages/better_auth-sso/test/better_auth/sso/*.rb` | New/updated tests per task |

---

## Out of scope (deliberately not in this plan)

- **`private_key_jwt` / mTLS for token endpoint** — Substantial new configuration, crypto, and test surface; treat as a separate feature.
- **Rewriting SLO XML handling to a full XML stack** — High effort; current behavior stays; only non-goals above are listed.
- **Lazy-loading `ruby-saml` for OIDC-only apps** — Invasive `require` graph and regression risk; product decision.
- **Splitting `plugins/sso.rb` into smaller files** — Valuable later, not required for these fixes.
- **Changing SAML vs OIDC `disable_implicit_sign_up` / `requestSignUp` semantics to match upstream** — Would change production behavior; needs product sign-off and a dedicated migration plan.
- **Unifying `needs_runtime_discovery?` between `OIDC::Discovery` and the plugin** — Small follow-up once this plan lands.

---

### Task 1: SAML config — correct SSO error string and validate logout URL

**Files:**
- Modify: `packages/better_auth-sso/lib/better_auth/plugins/sso.rb` (`sso_validate_saml_config!`, ~668–691)
- Test: add `packages/better_auth-sso/test/better_auth/sso/saml_config_validation_test.rb` (preferred; do not add to `oidc_test.rb`)

- [x] **Step 1: Add failing test for wrong message and missing SLO validation**

Create `packages/better_auth-sso/test/better_auth/sso/saml_config_validation_test.rb`:

```ruby
# frozen_string_literal: true

require "test_helper"

class SamlConfigValidationTest < Minitest::Test
  def test_single_sign_on_service_uses_sso_error_message
    err = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_config!(
        {single_sign_on_service: "not-a-url", entry_point: "https://idp.example.com/sso"},
        {}
      )
    end
    assert_includes err.message, "singleSignOnService"
    refute_includes err.message, "singleLogoutService"
  end

  def test_single_logout_service_validated_when_present
    err = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_config!(
        {single_logout_service: ":::bad", entry_point: "https://idp.example.com/sso"},
        {}
      )
    end
    assert_equal "BAD_REQUEST", err.status
  end
end
```

Run from repo root or package dir:

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-sso && bundle exec ruby -I test test/better_auth/sso/saml_config_validation_test.rb
```

Expected: **FAIL** (wrong message and/or SLO not validated).

- [x] **Step 2: Implement in `sso_validate_saml_config!`**

In `packages/better_auth-sso/lib/better_auth/plugins/sso.rb`, replace the `single_sign_on_service` block and add SLO validation:

```ruby
      sso_validate_url!(saml_config[:entry_point], "SAML entryPoint must be a valid URL") unless saml_config[:entry_point].to_s.empty?
      unless saml_config[:single_sign_on_service].to_s.empty?
        sso_validate_url!(saml_config[:single_sign_on_service], "SAML singleSignOnService must be a valid URL")
      end
      unless saml_config[:single_logout_service].to_s.empty?
        sso_validate_url!(saml_config[:single_logout_service], "SAML singleLogoutService must be a valid URL")
      end
```

- [x] **Step 3: Re-run test — expect PASS**

- [ ] **Step 4: Commit** *(not run; no commit requested)*

```bash
git add packages/better_auth-sso/lib/better_auth/plugins/sso.rb packages/better_auth-sso/test/better_auth/sso/saml_config_validation_test.rb
git commit -m "fix(sso): validate SAML SSO/SLO URLs with correct error messages"
```

---

### Task 2: Rename typo error code `INSUFICCIENT_ACCESS` → `INSUFFICIENT_ACCESS`

**Files:**
- Modify: `packages/better_auth-sso/lib/better_auth/plugins/sso.rb` (~1631)
- Modify: `packages/better_auth-sso/test/better_auth/sso/domain_verification_test.rb` (all assertions on this code)

- [x] **Step 1: Failing test — update expectations first**

Change every `assert_equal "INSUFICCIENT_ACCESS"` to `assert_equal "INSUFFICIENT_ACCESS"` in `domain_verification_test.rb`.

Run:

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-sso && bundle exec ruby -I test test/better_auth/sso/domain_verification_test.rb
```

Expected: **FAIL** until plugin updated.

- [x] **Step 2: Fix plugin**

```ruby
raise APIError.new("FORBIDDEN", message: "User must be owner of or belong to the SSO provider organization", code: "INSUFFICIENT_ACCESS")
```

- [x] **Step 3: Grep for leftover typo**

```bash
rg "INSUFICCIENT" packages/better_auth-sso
```

Expected: no matches.

- [ ] **Step 4: Commit** *(not run; no commit requested)*

```bash
git add packages/better_auth-sso/lib/better_auth/plugins/sso.rb packages/better_auth-sso/test/better_auth/sso/domain_verification_test.rb packages/better_auth-sso/CHANGELOG.md
git commit -m "fix(sso)!: correct INSUFFICIENT_ACCESS error code spelling"
```

Document **breaking change** in `CHANGELOG.md` under a `### Changed` or `### Fixed` section for API consumers matching codes.

---

### Task 3: OIDC — bind signed `state["providerId"]` to `/sso/callback/:providerId`

**Files:**
- Modify: `packages/better_auth-sso/lib/better_auth/plugins/sso.rb` (`sso_handle_oidc_callback`, after `state` is resolved and before loading provider)
- Test: add a new test in `packages/better_auth-sso/test/better_auth/sso_oidc_test.rb` (same `SECRET`, `BetterAuth.auth`, and `auth.api.callback_sso` style as `test_oidc_callback` around lines 224–270)

- [x] **Step 1: Add test that mismatched path vs state redirects with error**

1. Reuse the existing OIDC provider registration + `BetterAuth::Crypto.sign_jwt` state pattern from `test_oidc_sign_in` / `test_oidc_callback` in the same file.
2. Build `state` JWT with `providerId: "oidc"` (or the registered id) and a valid `callbackURL`.
3. Call `auth.api.callback_sso(params: {providerId: "other-id"}, query: {code: "x", state: state}, as_response: true)` so the **URL segment** does not match `state["providerId"]`.
4. Assert the Rack response is a **redirect** whose `Location` includes the app error/callback URL and an error code for invalid state (e.g. `invalid_state` and/or `provider mismatch` in query), matching `sso_append_error` output used elsewhere in these tests.

Also add a parallel test for `auth.api.callback_sso_shared(query: {code: "x", state: state}, as_response: true)` where the state JWT contains `providerId: "oidc"` but the shared callback route has no URL segment to bind against; in this case the providerId from state is the only source of truth, so the test should assert the callback succeeds (or at least does not fail with "provider mismatch").

Run the new test only: expect **FAIL** until the guard in Step 2 exists.

- [x] **Step 2: Add guard in `sso_handle_oidc_callback`**

Immediately after `return ctx.redirect(... invalid_state ...)` when state missing, and after OAuth error handling, add:

```ruby
      state_pid = state["providerId"] || state[:providerId]
      if state_pid.to_s != provider_id.to_s
        return sso_redirect(ctx, sso_append_error(error_url, "invalid_state", "provider mismatch"))
      end
```

Use existing `error_url` / `sso_append_error` patterns.

- [x] **Step 3: Run OIDC tests — PASS**

- [ ] **Step 4: Commit** *(not run; no commit requested)*

```bash
git commit -m "fix(sso): reject OIDC callback when state providerId does not match route"
```

---

### Task 4: OIDC — `nonce` in authorize request and ID token verification

> **Upstream note:** upstream `better-auth` (v1.6.9) does not include OIDC `nonce`. This is a Ruby-specific hardening enhancement, not upstream parity.

**Files:**
- Modify: `packages/better_auth-sso/lib/better_auth/plugins/sso.rb`: `sso_sign_in_endpoint` (OIDC branch), `sso_oidc_authorization_url`, `sso_handle_oidc_callback`, `sso_oidc_user_info`, `sso_validate_oidc_id_token`

- [x] **Step 1: Failing test**

In OIDC callback tests, assert that generated authorize URL includes `nonce=` after sign-in (decode query). Assert ID token validation fails when `nonce` claim wrong (if tests construct tokens — otherwise integration-level: mock JWKS path).

At minimum: test **authorize URL contains nonce** using existing sign-in flow.

Run: **FAIL** until implemented.

- [x] **Step 2: Add `nonce` to OIDC state**

In `sso_sign_in_endpoint`, inside `if provider["oidcConfig"] && provider_type != "saml"`:

```ruby
          state_data[:nonce] = BetterAuth::Crypto.random_string(32)
```

- [x] **Step 3: Add `nonce` query param in `sso_oidc_authorization_url`**

After building `query`, merge nonce from decoded state:

```ruby
      decoded = sso_decode_state(state, ctx.context.secret)
      n = decoded && (decoded["nonce"] || decoded[:nonce])
      query[:nonce] = n if n && !n.to_s.empty?
```

- [x] **Step 4: Pass expected nonce into ID token validation**

Change `sso_oidc_user_info` signature to accept `expected_nonce` and forward it to `sso_validate_oidc_id_token`:

```ruby
    def sso_oidc_user_info(ctx, oidc_config, tokens, plugin_config, expected_nonce: nil)
      # ... existing logic ...
      elsif tokens[:id_token]
        return {_sso_error: "jwks_endpoint_not_found"} if oidc_config[:jwks_endpoint].to_s.empty?

        sso_validate_oidc_id_token(
          tokens[:id_token],
          jwks_endpoint: oidc_config[:jwks_endpoint],
          audience: oidc_config[:client_id],
          issuer: oidc_config[:issuer],
          fetch: plugin_config[:oidc_jwks_fetch],
          expected_nonce: expected_nonce
        ) || {_sso_error: "token_not_verified"}
      # ...
    end
```

Also update the call site in `sso_handle_oidc_callback`:

```ruby
      user_info = sso_oidc_user_info(ctx, oidc_config, tokens, config, expected_nonce: state["nonce"] || state[:nonce])
```

Extend `sso_validate_oidc_id_token` signature:

```ruby
    def sso_validate_oidc_id_token(token, jwks_endpoint:, audience:, issuer:, fetch: nil, expected_nonce: nil)
      jwks = sso_fetch_oidc_jwks(jwks_endpoint, fetch: fetch)
      payload, = ::JWT.decode(
        token.to_s,
        nil,
        true,
        algorithms: %w[RS256 RS384 RS512 ES256 ES384 ES512],
        jwks: jwks,
        aud: audience,
        verify_aud: true,
        iss: issuer,
        verify_iss: true
      )
      if expected_nonce && !expected_nonce.to_s.empty?
        token_nonce = payload["nonce"] || payload[:nonce]
        return nil if token_nonce.to_s.empty?
        return nil unless BetterAuth::Crypto.constant_time_compare(token_nonce.to_s, expected_nonce.to_s)
      end
      payload
    rescue
      nil
    end
```

- [x] **Step 5: Run package tests — PASS**

- [ ] **Step 6: Commit + CHANGELOG** *(CHANGELOG updated; commit not run)*

```bash
git commit -m "feat(sso): add OIDC nonce for authorization and id_token verification"
```

---

### Task 5: Domain verification — exact TXT match (no substring)

**Files:**
- Modify: `packages/better_auth-sso/lib/better_auth/plugins/sso.rb` (`sso_verify_domain_endpoint` block ~527–531)
- Test: `packages/better_auth-sso/test/better_auth/sso/domain_verification_test.rb`

- [x] **Step 1: Failing test**

Add a case where a TXT record is `prefix=token-value` but verification expects only `prefix=token` inside a longer malicious string — substring would pass; exact must fail.

Example:

```ruby
# Stub resolver returns ["evil-prefix=token-value-attacker"]
# expected remains "#{identifier}=#{token}"
# assert_raises DOMAIN_VERIFICATION_FAILED
```

Run: **FAIL**.

- [x] **Step 2: Add helper and use in verify endpoint**

```ruby
    def sso_txt_record_exact_match?(records, expected)
      Array(records).flatten.any? do |record|
        record.to_s.strip == expected
      end
    end
```

Replace:

```ruby
        unless sso_txt_record_exact_match?(records, expected)
```

- [ ] **Step 3: PASS + commit** *(tests passed; commit not run)*

```bash
git commit -m "fix(sso): require exact TXT match for domain verification"
```

---

### Task 6: `SAMLState` — qualify `BetterAuth::APIError`

**Files:**
- Modify: `packages/better_auth-sso/lib/better_auth/sso/saml_state.rb`
- Test: `packages/better_auth-sso/test/better_auth/sso/saml_state_test.rb` (assert `BetterAuth::APIError`)

- [x] **Step 1: Change line 10**

```ruby
        raise BetterAuth::APIError.new("BAD_REQUEST", message: "callbackURL is required")
```

> **Side note:** `packages/better_auth-sso/lib/better_auth/sso/oidc/errors.rb` also uses bare `APIError`. It resolves correctly at runtime, but for consistency you may apply the same qualification there in a follow-up.

- [x] **Step 2: Run `saml_state_test.rb` — PASS**

- [ ] **Step 3: Commit** *(not run; no commit requested)*

```bash
git commit -m "refactor(sso): qualify APIError in SAMLState"
```

---

### Task 7: Declare `jwt` as a direct dependency

**Files:**
- Modify: `packages/better_auth-sso/better_auth-sso.gemspec`
- Reference: `packages/better_auth/better_auth.gemspec` for compatible `jwt` version constraint

- [x] **Step 1: Copy the `jwt` version line from `better_auth.gemspec`**

Use the same constraint as core (as of 2026-05-03):

```ruby
  spec.add_dependency "jwt", "~> 2.8"
```

- [x] **Step 2: `bundle check` in package + run full SSO tests**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-sso && bundle install && bundle exec rake test
```

Expected: **PASS**

- [ ] **Step 3: Commit** *(not run; no commit requested)*

```bash
git commit -m "build(sso): declare jwt runtime dependency explicitly"
```

---

### Task 8: SAML SP metadata — XML body regression test

**Files:**
- Test: add to `packages/better_auth-sso/test/better_auth/sso/routes/sso_test.rb` or `saml_test.rb`
- Modify only if test proves bug: `sso_sp_metadata_endpoint` should return raw XML string; `Endpoint::Result` already treats `String` as raw body (see `better_auth` `endpoint.rb`).

- [x] **Step 1: Integration-style test**

GET `/sso/saml2/sp/metadata?providerId=...` without `format=json`: assert `Content-Type` includes `application/samlmetadata+xml` or `xml`, and body starts with `<?xml` or `<EntityDescriptor` (depending on generator).

Run: document actual behavior; if Content-Type is wrong, set header and pass **string** response (already string — verify headers merge).

- [x] **Step 2: Fix only if failing** *(no production fix needed)*

`Result.to_response` already treats `String` responses as raw body arrays and preserves custom headers via `merge`, so `ctx.json(metadata)` after `ctx.set_header("content-type", "application/samlmetadata+xml")` should already return valid XML with the correct content type. If the test proves otherwise, replace with:

```ruby
          ctx.set_header("content-type", "application/samlmetadata+xml; charset=utf-8")
          ctx.json(metadata)
```

Confirm in test.

- [ ] **Step 3: Commit** *(not run; no commit requested)*

```bash
git commit -m "test(sso): cover SAML SP metadata XML response"
```

---

## Self-review (spec coverage)

| Finding from review | Task |
|---------------------|------|
| Wrong SSO vs SLO validation message | Task 1 |
| Typo `INSUFICCIENT_ACCESS` | Task 2 |
| OIDC path vs state provider mix-up | Task 3 |
| Missing OIDC `nonce` | Task 4 |
| Domain TXT substring weakness | Task 5 |
| Unqualified `APIError` in SAMLState | Task 6 |
| Transitive-only `jwt` dependency | Task 7 |
| SP metadata XML concern | Task 8 |

## Self-review (placeholder scan)

No `TBD` / vague “add validation” steps; each task names concrete methods and files.

---

## Agent review notes

Issues found and corrected in this plan revision:

1. **Architecture clarification:** Removed the `constant_time_compare` reference from the architecture summary because the SSO plugin does not perform any plain-text bearer-token comparisons that would require it (unlike SCIM `default_scim`).
2. **Task 1 test target:** Specified that the SAML config test should live in a new `saml_config_validation_test.rb`, not in `oidc_test.rb`.
3. **Task 3 test completeness:** Added a note to also cover the shared callback endpoint (`callback_sso_shared`) to ensure the providerId binding logic does not regress the shared-flow behavior.
4. **Task 4 missing signature change:** The original plan did not explicitly state that `sso_oidc_user_info` must accept and forward `expected_nonce`. Added the required signature change and call-site update in `sso_handle_oidc_callback`.
5. **Task 4 upstream deviation:** Added an explicit note that OIDC `nonce` is not present in upstream v1.6.9; this is a Ruby-specific hardening enhancement.
6. **Task 6 scope note:** Added a side note about `oidc/errors.rb` also using bare `APIError`, which is consistent but unqualified.
7. **Task 8 behavior note:** Clarified that the current implementation likely already returns raw XML correctly because `Result.to_response` handles String responses as raw body; the task is primarily a regression test.

---

## Execution handoff

**Plan saved to:** `.docs/plans/2026-05-03-2045--sso-security-and-correctness.md`

**Execution options:**

1. **Subagent-driven (recommended)** — One subagent per task, review between tasks (`subagent-driven-development` skill).

2. **Inline execution** — Run tasks in one session with checkpoints (`executing-plans` skill).

Which approach do you want?

---

## Execution notes

- 2026-05-04: Executed inline in `packages/better_auth-sso` after comparing against upstream `v1.6.9`.
- Upstream still uses substring TXT matching and the `INSUFICCIENT_ACCESS` typo; implemented exact TXT matching and corrected `INSUFFICIENT_ACCESS` as Ruby-specific hardening/API correctness.
- Upstream does not include OIDC nonce; implemented nonce as Ruby-specific hardening because this port verifies ID tokens via JWKS.
- SAML SP metadata already returned XML correctly; added regression coverage only.
- Commit steps from the original plan were not run because this execution did not request commits.
