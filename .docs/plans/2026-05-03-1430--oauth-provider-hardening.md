# OAuth Provider Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Fix security and consistency issues identified in `better_auth-oauth-provider` and `better_auth` (`oauth_protocol`), aligned with expected OAuth 2 / OIDC behavior and with upstream where applicable, without opening a parallel total-parity project with TypeScript.

**Architecture:** Changes touch the core (`OAuthProtocol` in `packages/better_auth`) for protocol rules (refresh bound to client, minimal persistence on revocation) and the plugin (`packages/better_auth-oauth-provider`) for consent, metadata, issuer (`iss`), and rate limits. Tests follow Minitest in the plugin gem and in the core according to the modified file.

**Tech Stack:** Ruby 3.x, Minitest, Rack, gem `better_auth`, gem `better_auth-oauth-provider`.

---

## Out of scope (and why)

| Topic | Reason |
|-------|--------|
| Full upstream parity: PAR (`request_uri`), well-known under issuer path, `after` hooks to resume authorize after cookie | Several weeks and multiple subsystems; deserves a separate plan per subsystem. |
| Enforce `state` on `/oauth2/authorize` by default | Breaks existing clients; if desired, it must be an **explicit** configuration option in a separate change. |
| Constant-time comparison in PKCE (`verify_pkce!`) | High-entropy inputs; marginal benefit vs. review cost. |
| Abstract "multi-worker atomicity" without defining a shared store (Redis/DB) | Deployment decision; code can document the requirement without inventing infrastructure here. |
| Expand loopback rules (`localhost` vs `127.0.0.1`) without downstream test cases | Behavioral change that can break integrations; requires RFC research + dedicated tests. |

---

## File map

| File | Responsibility after the plan |
|------|------------------------------|
| `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb` | Validate `clientId` on refresh; optionally merge `id` from access token after `adapter.create`; revocation helper that updates adapter when an `id` is present. |
| `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/consent.rb` | Current session = session that created the pending consent; `reference_id` stable from the stored pending consent. |
| `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/token.rb` | Normalized `issuer` using `validate_issuer_url` on refresh and client_credentials. |
| `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/metadata.rb` | `registration_endpoint` only when DCR is enabled. |
| `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/revoke.rb` | After in-memory revocation, persist `revoked` in the adapter when the record has an `id`. |
| `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/rate_limit.rb` | Rules for `/oauth2/continue`, `/oauth2/consent`, `/oauth2/end-session`. |
| `packages/better_auth/lib/better_auth/crypto.rb` (if applicable) + `oauth_protocol.rb` `id_token` | Sign ID token with non-public material when a usable client secret exists (see Task 8). |
| `packages/better_auth-oauth-provider/test/...` and `packages/better_auth/test/...` | New or expanded tests per task. |

---

### Task 1: Bind refresh token to the authenticated client at the token endpoint

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb` (`refresh_tokens` method, ~487–500)
- Test: `packages/better_auth/test/better_auth/plugins/oauth_protocol_test.rb` (create if absent; if the core already has refresh tests, expand the existing file)

- [x] **Step 1: Write a failing test**

Goal: with a refresh token issued for `clientId` **A**, a request to the token endpoint authenticated as client **B** (client_secret of B) must respond `invalid_grant` (or equivalent `BAD_REQUEST` with message `invalid_grant`), not issue tokens for B.

Use the same pattern as other core tests: build `store`, clients A and B, `issue_tokens` for A with refresh, then call `OAuthProtocol.refresh_tokens` with `client: B` and A's refresh string — it must raise `APIError`.

```ruby
# Minimal assertion example (adjust to core test_helper helpers)
error = assert_raises(BetterAuth::APIError) do
  BetterAuth::OAuthProtocol.refresh_tokens(
    ctx,
    store,
    model: "oauthAccessToken",
    client: client_b_hash,
    refresh_token: refresh_token_string_for_client_a,
    # ...
  )
end
assert_equal "BAD_REQUEST", error.code
assert_match(/invalid_grant/i, error.message.to_s)
```

- [x] **Step 2: Run the test**

Run: `cd /Users/sebastiansala/projects/better-auth/packages/better_auth && bundle exec ruby -Itest test/better_auth/plugins/oauth_protocol_test.rb -n test_refresh_rejects_mismatched_client`

Expected: FAIL (error not raised or different assertion).

- [x] **Step 3: Minimal implementation**

In `refresh_tokens`, after checking that `data` exists, is not revoked, and has not expired, and **before** validating reduced scopes, add:

```ruby
client_data = stringify_keys(client)
unless data["clientId"].to_s == client_data["clientId"].to_s
  raise APIError.new("BAD_REQUEST", message: "invalid_grant")
end
```

- [x] **Step 4: Run the test**

Expected: PASS.

- [x] **Step 5: Commit skipped per package instruction**

```bash
git add packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb packages/better_auth/test/better_auth/plugins/oauth_protocol_test.rb
git commit -m "fix(oauth): reject refresh token when authenticated client differs"
```

---

### Task 2: Verify that POST /oauth2/consent belongs to the same session that created the pending consent

**Files:**
- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/consent.rb` (~7–30)
- Test: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/consent_test.rb` (create) or expand `test/better_auth/oauth_provider/oauth_provider_test.rb` if it already groups consent logic

- [x] **Step 1: Write a failing test**

Simulate a real flow: sign up **User A**, start an authorize flow to get a `consent_code` stored in `store[:consents]`. Then sign up **User B** and POST to `/oauth2/consent` with B's cookie and the consent_code from A. The endpoint must return an error (e.g. `FORBIDDEN` or `UNAUTHORIZED`), not a success JSON with `redirectURI`.

```ruby
# Pseudocode using integration helpers
auth = build_auth(scopes: ["openid"])
cookie_a = sign_up_cookie(auth, email: "a@example.com")
client = create_client(auth, cookie_a, scope: "openid")
status, headers, = authorize_response(auth, cookie_a, client, scope: "openid", prompt: "consent")
params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
consent_code = params.fetch("consent_code")

cookie_b = sign_up_cookie(auth, email: "b@example.com")
error = assert_raises(BetterAuth::APIError) do
  auth.api.o_auth2_consent(headers: {"cookie" => cookie_b}, body: {accept: true, consent_code: consent_code})
end
assert_equal "FORBIDDEN", error.code # or UNAUTHORIZED depending on implementation
```

- [x] **Step 2: Run the test**

Expected: FAIL.

- [x] **Step 3: Implementation**

Change line 9 to use `allow_nil: true` so the explicit session check is reachable:

```ruby
current_session = Routes.current_session(ctx, allow_nil: true)
```

Then, right after validating `consent_code` and expiration:

```ruby
raise APIError.new("UNAUTHORIZED", message: "session required") unless current_session
unless current_session[:user]["id"].to_s == consent[:session][:user]["id"].to_s
  raise APIError.new("FORBIDDEN", message: "consent session mismatch")
end
```

- [x] **Step 4: Run the test**

Expected: PASS.

- [x] **Step 5: Commit skipped per package instruction**

```bash
git add packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/consent.rb packages/better_auth-oauth-provider/test/...
git commit -m "fix(oauth-provider): bind consent approval to original user session"
```

---

### Task 3: Normalize `issuer` on refresh and client_credentials the same as on authorization_code

**Files:**
- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/token.rb` (`REFRESH_GRANT` branch ~59–62, `CLIENT_CREDENTIALS_GRANT` branch ~58)
- Test: expand `test/better_auth/oauth_provider/token_test.rb` or an integration test that asserts `iss` in the ID token / claims if an issuer assertion already exists

- [x] **Step 1: Code change (no placeholder)**

In **both** branches `when OAuthProtocol::REFRESH_GRANT` and `when OAuthProtocol::CLIENT_CREDENTIALS_GRANT`, replace `issuer: OAuthProtocol.issuer(ctx)` with:

```ruby
issuer: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))
```

(The refresh branch is around line 62; client_credentials around line 58. Both are long one-liners — only the `issuer` argument changes.)

- [x] **Step 2: Test**

If a metadata or token test compares the AS issuer with the emitted one, run:

`cd packages/better_auth-oauth-provider && bundle exec rake test`

If there is no coverage, add a minimal integration test that hits the token endpoint with `client_credentials` and verifies that the JWT access token (when `jwt_access_token`) carries `iss` equal to the normalized value, or document in the commit that this is only a normalization aligned with authorize.

- [x] **Step 3: Commit skipped per package instruction**

```bash
git commit -am "fix(oauth-provider): use validate_issuer_url for refresh and client_credentials tokens"
```

---

### Task 4: Omit `registration_endpoint` from metadata when DCR is disabled

**Files:**
- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/metadata.rb` (both endpoints ~10–26 and ~38–55)
- Test: `test/better_auth/oauth_provider/metadata_test.rb`

- [x] **Step 1: Write a failing test**

With `allow_dynamic_client_registration: false`, GET `/.well-known/oauth-authorization-server` must **not** contain the key `registration_endpoint` (prefer **absence of the key** over `nil`).

- [x] **Step 2: Implementation**

Build `metadata` as today, but only add:

```ruby
metadata[:registration_endpoint] = "#{base}/oauth2/register" if config[:allow_dynamic_client_registration]
```

Remove the fixed line that always assigns `registration_endpoint` in both hashes.

- [x] **Step 3: Run metadata tests**

`bundle exec ruby -Itest test/better_auth/oauth_provider/metadata_test.rb`

- [x] **Step 4: Commit skipped per package instruction**

```bash
git commit -am "fix(oauth-provider): advertise registration_endpoint only when DCR enabled"
```

---

### Task 5: Pin `reference_id` on approved consent to the pending consent's value

**Files:**
- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/consent.rb` (~27–28)
- Test: consent test covering `post_login.consentReferenceId` or session-based reference if a helper like `oauth_consent_reference` exists

- [x] **Step 1: Implementation**

Replace:

```ruby
reference_id = oauth_consent_reference(config, current_session, granted_scopes) || consent[:reference_id]
```

with:

```ruby
reference_id = consent[:reference_id]
```

Reasoning: the pending consent already fixed `reference_id` in `authorize.rb` when creating the `store[:consents]` entry; recalculating it with `current_session` can desynchronize rows in `oauthConsent` relative to the authorization flow. If `consent[:reference_id]` is `nil`, `oauth_authorization_redirect` falls back to `client_reference_id` (the client's own `referenceId`), which is the correct default behavior.

- [x] **Step 2: Tests**

Run the oauth-provider suite. If a scenario fails because it relied on the intentional `post_login` override, evaluate a dedicated callback in a **separate** plan; for this plan the source of truth is the stored pending consent.

- [x] **Step 3: Commit skipped per package instruction**

```bash
git commit -am "fix(oauth-provider): use pending consent reference_id on approval"
```

---

### Task 6: Persist revocation in adapter when the opaque token has an `id`

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb` — in `issue_tokens`, after `adapter.create` for the opaque access token (~464), merge the returned `id` into the in-memory record.
- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/revoke.rb` — if the record has `"id"`, call `adapter.update` on model `oauthAccessToken` or `oauthRefreshToken` according to the resolved hint.
- Test: core + oauth-provider revoke

- [x] **Step 1: Merge access token `id` into memory (core)**

Replace the block that only calls `ctx.context.adapter.create` with something equivalent to:

```ruby
created_row = ctx.context.adapter.create(model: model, data: record)
created = stringify_keys(created_row || {})
record = record.merge("id" => created["id"]) if created["id"]
stored_record = record.merge("user" => user, "session" => session_data, "client" => client_data)
store[:tokens][access_token_value] = stored_record
store[:tokens][access_token] = stored_record
```

(Preserve the exact file structure; do not duplicate keys unnecessarily.)

- [x] **Step 2: Persist revocation (plugin)**

After `token["revoked"] = Time.now`, if `token["id"]` is present, determine whether the token is an access token or a refresh token and persist accordingly:

```ruby
if (token = OAuthProtocol.find_token_by_hint(config[:store], body["token"].to_s, body["token_type_hint"], prefix: config[:prefix]))
  token["revoked"] = Time.now
  if token["id"]
    hint = body["token_type_hint"].to_s
    access_value = OAuthProtocol.strip_prefix(body["token"].to_s, config[:prefix], :access_token)
    refresh_value = OAuthProtocol.strip_prefix(body["token"].to_s, config[:prefix], :refresh_token)

    is_access = hint == "access_token" || (access_value && config[:store][:tokens][access_value] == token)
    is_refresh = hint == "refresh_token" || (refresh_value && config[:store][:refresh_tokens][refresh_value] == token)

    if is_access && OAuthProtocol.schema_model?(ctx, "oauthAccessToken")
      ctx.context.adapter.update(model: "oauthAccessToken", where: [{field: "id", value: token["id"]}], update: {revoked: token["revoked"]})
    end

    if is_refresh && OAuthProtocol.schema_model?(ctx, "oauthRefreshToken")
      ctx.context.adapter.update(model: "oauthRefreshToken", where: [{field: "id", value: token["id"]}], update: {revoked: token["revoked"]})
    end
  end
end
```

- [x] **Step 3: Tests**

Write a revocation test using a memory or test adapter that verifies the DB record has `revoked` set after revoke when the token was created with an `id`.

- [x] **Step 4: Commit skipped per package instruction**

```bash
git commit -am "fix(oauth): persist token revocation and surface access token ids from adapter"
```

---

### Task 7: Expand rate limits to continue, consent, and end-session

**Files:**
- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/rate_limit.rb`
- Modify: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb` — update `test_plugin_exposes_upstream_rate_limit_rules` and the `oauth_rate_limit_path` helper to include the new paths
- Test: `test/better_auth/oauth_provider/rate_limit_test.rb`

- [x] **Step 1: Add three rules** with keys `:continue`, `:consent`, `:end_session` and exact paths:

```ruby
oauth_rate_limit_rule(rate_limit, :continue, "/oauth2/continue", window: 60, max: 40),
oauth_rate_limit_rule(rate_limit, :consent, "/oauth2/consent", window: 60, max: 40),
oauth_rate_limit_rule(rate_limit, :end_session, "/oauth2/end-session", window: 60, max: 30),
```

- [x] **Step 2: Update existing test that enumerates paths**

In `oauth_provider_test.rb`:
- Add the three new paths to the `oauth_rate_limit_path` helper's hardcoded list.
- Update `test_plugin_exposes_upstream_rate_limit_rules` so its expected `paths` array includes the new endpoints (or disable them in that test's config if you want to keep the assertion minimal).

- [x] **Step 3: Test**

Assertion that the array includes matchers for those paths (or an integration test if `rate_limit_test.rb` already tests by path).

- [x] **Step 4: Commit skipped per package instruction**

```bash
git commit -am "feat(oauth-provider): rate limit continue, consent, and end-session"
```

---

### Task 8: Harden the ID token HMAC key (do not use the public `clientId` as the sole secret)

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb` — new key helper, and the `Crypto.sign_jwt` branch in `id_token` (~729–732)
- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/logout.rb` — `verify_jwt` with the same key
- Test: `packages/better_auth/test/better_auth/plugins/oauth_protocol_test.rb` (new) or expand existing `id_token` tests; `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/logout_test.rb`

- [x] **Step 1: Add derived key helper (core)**

In `OAuthProtocol` (same module as `id_token`), add as a `module_function`:

```ruby
def id_token_hs256_key(ctx, client_id)
  label = client_id.to_s.empty? ? "better-auth" : client_id.to_s
  OpenSSL::HMAC.digest("SHA256", ctx.context.secret.to_s, "oidc.id_token.#{label}")
end
```

Reasoning: `client_id` is public; mixing it with `ctx.context.secret` (server-only) prevents forging ID tokens knowing only the client identifier. `Crypto.sign_jwt` and `verify_jwt` accept a binary string (byte string) for HS256.

- [x] **Step 2: Use the key in `id_token`**

Replace the third argument of `Crypto.sign_jwt` when there is no custom `signer`:

```ruby
Crypto.sign_jwt(
  payload,
  id_token_hs256_key(ctx, client_id),
  expires_in: 3600
)
```

- [x] **Step 3: Verification in logout**

In `logout.rb`, replace:

```ruby
payload = Crypto.verify_jwt(id_token_hint, client_data["clientId"])
```

with:

```ruby
payload = Crypto.verify_jwt(
  id_token_hint,
  OAuthProtocol.id_token_hs256_key(ctx, client_data["clientId"])
)
```

- [x] **Step 4: Tests**

- Core: a JWT signed with the old key (`clientId` as plain string) must **fail** verification with the new derived key.
- Logout: happy-path flow with a token issued after the change must delete the session; a token signed with the old key must produce an error.

- [x] **Step 5: CHANGELOG and breaking-change note**

Document in `packages/better_auth/CHANGELOG.md` and `packages/better_auth-oauth-provider/CHANGELOG.md`: existing HS256 ID tokens will stop validating for RP-initiated logout until they are re-obtained (expected behavior on a signing key rotation).

- [x] **Step 6: Commit skipped per package instruction**

```bash
git commit -m "fix(oauth): derive HS256 ID token key from server secret and client id"
```

---

## Self-review (internal checklist)

1. **Analysis coverage:** refresh↔client, consent session, consistent `iss`, metadata DCR, `reference_id`, persisted revocation, rate limits, ID token/logout — all covered. **Not** covered here: PAR, discovery by issuer path, mandatory `state`, PKCE constant-time (excluded above).
2. **Placeholders:** none; Task 8 includes reference code for the derived key and call sites.
3. **Consistency:** `invalid_grant` is already used by the project for invalid refresh; `consent session mismatch` maps to an HTTP code coherent with the existing `APIError` usage.
4. **Corrections applied vs. original draft:**
   - Fixed skill references (`subagent-driven-development` / `executing-plans` without `superpowers:` prefix).
   - Task 1: corrected core test file path to `test/better_auth/plugins/oauth_protocol_test.rb`.
   - Task 2: added `allow_nil: true` to `Routes.current_session` so the explicit session check is reachable; replaced mock-based test with a real integration test using two user cookies.
   - Task 5: documented the fallback to `client_reference_id` when `consent[:reference_id]` is nil.
   - Task 6: added concrete code to distinguish access vs. refresh tokens on revocation and persist both; preserved `"client"` in the stored record.
   - Task 7: removed unnecessary `oauth_provider.rb` modification note; added required updates to `oauth_provider_test.rb` and the `oauth_rate_limit_path` helper.
   - Task 8: simplified call sites by passing `client_id` directly to the helper; clarified `module_function` requirement.

---

**Plan complete and saved to** `.docs/plans/2026-05-03-1430--oauth-provider-hardening.md`.

## Execution note - 2026-05-05

Implemented inline after comparing upstream `oidc-provider` behavior. The ID token HS256 hardening was adapted to use the OAuth client's `clientSecret` when present, matching upstream's non-JWT-plugin behavior; Ruby falls back to a server-secret-derived key only when no usable client secret exists. No per-task commits were created because package-level instructions say not to commit unless the user explicitly asks.

**Execution options:**

1. **Subagent-Driven (recommended)** — One subagent per task, review between tasks. Sub-skill: `subagent-driven-development`.
2. **Inline execution** — Tasks in this session with `executing-plans`.

Which do you prefer?
