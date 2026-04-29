# Passkey Upstream Parity Follow-Up Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:test-driven-development` for every behavior change. Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the residual deltas between `packages/better_auth-passkey` and the upstream `packages/passkey` (Better Auth `v1.6.9`) that remain after `2026-04-29-passkey-upstream-parity.md`. Focus on validation surface, error code parity for ownership checks, RP id resolution, and JSON wire shape on registration responses.

**Architecture:** Keep the public Ruby `BetterAuth::Plugins.passkey(options)` API stable, retaining `snake_case` option keys. Use the existing scoped `WebAuthn::RelyingParty` configuration. Patch the validation, ownership, and credential-descriptor paths to mirror upstream's `requireResourceOwnership` middleware semantics and `getRpID` / `excludeCredentials` shape.

**Tech Stack:** Ruby 3.4.9, Minitest, StandardRB, `webauthn` gem, Better Auth core session/routes, upstream Better Auth `packages/passkey` (v1.6.9).

---

## Summary Of Identified Deltas

The earlier parity plan implemented fresh-session enforcement, schema deep-merge, after-verification override, scoped WebAuthn config, and registration validation. The residual deltas are:

1. **Ownership check error code on `delete_passkey`**
   - Upstream's `requireResourceOwnership` raises `UNAUTHORIZED` with the `notFoundError` message (`PASSKEY_ERROR_CODES.PASSKEY_NOT_FOUND`) for both not-found and forbidden cases on delete (because no `forbiddenError` is provided). Ruby raises `UNAUTHORIZED` without a message body when the passkey belongs to another user. Apps observing the wire response see `null` instead of "Passkey not found".

2. **`excludeCredentials` shape**
   - Upstream returns `excludeCredentials: [{ id, transports }]` (no `type` field, mirroring `@simplewebauthn/server` output). Ruby returns `{id, type: "public-key", transports}`. The extra `type` field is harmless for browsers, but tests asserting upstream shape will diverge. Decide whether to keep the Ruby augmentation or drop it.

3. **`getRpID` parity**
   - Upstream uses `new URL(baseURL).hostname`. Ruby parses with `URI.parse` which fails for some valid base URLs that contain interpolated paths or trailing dots. Add tests for `https://example.com:8443/api/auth` (port stripped, no trailing colon), `http://localhost`, and the `URI::InvalidURIError` rescue path.

4. **`generate-authenticate-options` userVerification**
   - Upstream calls `generateAuthenticationOptions({rpID, userVerification: "preferred", extensions, ...})` and the result already contains `userVerification`. Ruby calls `WebAuthn::Credential.options_for_get` (no userVerification override), then merges `userVerification: "preferred"` into the JSON payload. Verify the `webauthn` gem's default in `options_for_get` is `"preferred"` so the manual merge is a no-op; otherwise tests asserting the upstream wire shape may differ.

5. **`generate-authenticate-options` empty `allowCredentials` removal**
   - Upstream **omits** `allowCredentials` from the JSON when no passkeys are linked to the session (or when there is no session). Ruby deletes `:allowCredentials` and `"allowCredentials"` from `payload`. Verify there is no `allow_credentials` snake_case leak through `as_json`.

6. **`generate-register-options` returns the upstream `excludeCredentials` from `generateRegistrationOptions`**
   - Upstream relies on `@simplewebauthn/server` to format `excludeCredentials` in base64url and to handle missing transports. Ruby maps over passkey records manually and joins/splits on commas. Add a regression test for a passkey whose `transports` is `nil` (must not emit a `transports: []` array; must omit the key entirely to match upstream output).

7. **`registration.afterVerification` empty `userId` semantics**
   - Upstream treats `result.userId` as falsy if `undefined` or empty string and otherwise validates it is a non-empty string before applying. Ruby returns `target_user_id` if the returned value is empty, but raises `RESOLVED_USER_INVALID` only when it is a non-string truthy value. Confirm the matrix: `nil`, `""`, `"abc"`, `123` (should raise), `true` (should raise).

8. **`afterVerification` mismatch error**
   - Upstream throws `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY` when the override targets another user. Ruby does the same but only when a session exists; for the pre-auth flow upstream does not enforce a session check, but it also rejects mismatch when both `result.userId` and `session?.user?.id` are present and different. Confirm Ruby behavior matches when `session` is `nil` (no enforcement) and emits the right error otherwise.

9. **Authentication flow `set_session_cookie` ordering**
   - Upstream `setSessionCookie(ctx, { session: s, user })` runs before `deleteVerificationByIdentifier`. Ruby preserves this ordering. OK, no action required, but add a regression test that asserts the cookie is set on a successful authentication.

10. **Update endpoint name validation**
    - Upstream's `updatePasskey` requires `name: z.string()` (any string). Ruby raises `VALIDATION_ERROR` when `name` is missing or not a string. OK, but ensure empty string `""` is allowed (upstream allows it). Add a test.

11. **Schema model name**
    - Upstream uses `passkey` (singular). Ruby uses `model_name: "passkeys"` (plural) intentionally for the SQL adapter. Document this as a Ruby-specific adaptation in the README and tests, and ensure `BetterAuth::Adapters::*` translate `model: "passkey"` to the `passkeys` storage table.

## File Structure

- Modify: `packages/better_auth-passkey/lib/better_auth/plugins/passkey.rb`
- Modify: `packages/better_auth-passkey/test/better_auth/passkey_test.rb`
- Modify: `packages/better_auth-passkey/README.md` and `docs/content/docs/plugins/passkey.mdx`

## Task List

### Task 1: Failing Parity Tests

**Files:**
- Modify: `packages/better_auth-passkey/test/better_auth/passkey_test.rb`

- [x] **Step 1: Test that delete forbidden returns the `PASSKEY_NOT_FOUND` message**

```ruby
def test_delete_passkey_for_another_user_returns_not_found_message
  err = assert_raises(BetterAuth::APIError) { delete_passkey!(other_users_passkey_id) }
  assert_equal "UNAUTHORIZED", err.code
  assert_equal "Passkey not found", err.message
end
```

- [x] **Step 2: Test for `excludeCredentials` shape parity**

```ruby
def test_register_options_exclude_credentials_match_upstream_shape
  options = generate_register_options!
  options[:excludeCredentials].each do |entry|
    refute_includes entry.keys, :type
    refute_includes entry.keys, "type"
    assert_kind_of String, entry[:id]
    assert(entry[:transports].nil? || entry[:transports].is_a?(Array))
  end
end
```

- [x] **Step 3: Test for transports omission**

```ruby
def test_register_options_omit_transports_when_passkey_has_none
  passkey_without_transports!
  options = generate_register_options!
  options[:excludeCredentials].each do |entry|
    refute_includes entry.keys, :transports
    refute_includes entry.keys, "transports"
  end
end
```

- [x] **Step 4: Test for RP id resolution**

```ruby
def test_rp_id_falls_back_to_hostname_with_port_stripped
  ctx = build_ctx(base_url: "https://example.com:8443/api/auth")
  rp_id = BetterAuth::Plugins.send(:passkey_rp_id, {}, ctx)
  assert_equal "example.com", rp_id
end

def test_rp_id_returns_localhost_when_base_url_is_invalid
  ctx = build_ctx(base_url: "not a url")
  rp_id = BetterAuth::Plugins.send(:passkey_rp_id, {}, ctx)
  assert_equal "localhost", rp_id
end
```

- [x] **Step 5: Test `afterVerification` empty/invalid `userId` matrix**

```ruby
def test_after_verification_user_id_matrix
  assert_equal default_user_id, register_with_after_verification(returning: nil)
  assert_equal default_user_id, register_with_after_verification(returning: "")
  assert_equal "linked-user", register_with_after_verification(returning: "linked-user")
  assert_raises(BetterAuth::APIError) { register_with_after_verification(returning: 123) }
  assert_raises(BetterAuth::APIError) { register_with_after_verification(returning: true) }
end
```

- [x] **Step 6: Test `update_passkey` accepts empty string name**

```ruby
def test_update_passkey_allows_empty_name_to_match_upstream
  result = update_passkey!(name: "")
  assert_equal "", result.dig(:passkey, :name)
end
```

- [x] **Step 7: Run the new tests**

```bash
cd packages/better_auth-passkey
rbenv exec bundle exec ruby -Itest test/better_auth/passkey_test.rb -n /shape|message|user_id_matrix|empty_name|rp_id/
```

Expected: failures across these tests until the implementation is updated.

**Result:** Initial run produced 2 failures (`test_register_options_exclude_credentials_match_upstream_shape`, `test_delete_passkey_for_another_user_returns_not_found_message`) on a `30 runs, 132 assertions, 2 failures, 0 errors, 0 skips` baseline. The remaining new tests already match upstream behavior with the existing implementation, so they passed on first run. A pre-existing test-helper bug was uncovered during this step: `build_auth` was missing `email_and_password: {enabled: true}` after a recent core change that disables email/password sign-up by default. Adding it brought the suite from 12 errors back to a clean baseline before the new tests were introduced.

### Task 2: Ownership Check Error Message Parity

**Files:**
- Modify: `packages/better_auth-passkey/lib/better_auth/plugins/passkey.rb`

- [x] **Step 1: Update `delete_passkey_endpoint`**

Replace the bare `raise APIError.new("UNAUTHORIZED")` with:

```ruby
raise APIError.new("UNAUTHORIZED", message: PASSKEY_ERROR_CODES.fetch("PASSKEY_NOT_FOUND")) unless passkey.fetch("userId") == session.fetch(:user).fetch("id")
```

- [x] **Step 2: Audit `update_passkey_endpoint`**

Confirmed: it already raises `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY` with `forbiddenError` semantics, mirroring upstream's `requireResourceOwnership({forbiddenError: PASSKEY_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY})`. No change required.

- [x] **Step 3: Run the delete test**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/passkey_test.rb -n test_delete_passkey_for_another_user_returns_not_found_message
```

Expected: PASS. Result: `1 runs, 3 assertions, 0 failures, 0 errors, 0 skips`.

- [x] **Step 4: Commit**

```bash
git commit -am "fix(passkey): emit PASSKEY_NOT_FOUND message on cross-user delete"
```

### Task 3: `excludeCredentials` And Transports Shape

**Files:**
- Modify: `packages/better_auth-passkey/lib/better_auth/plugins/passkey.rb`

- [x] **Step 1: Drop the extra `type` field for register exclude shape**

Update `passkey_credential_descriptor` so the registration excludeCredentials shape matches upstream. Either:

- Add a `kind:` argument that returns `{id, transports?}` for register and `{id, type: "public-key", transports?}` for authenticate (since `allowCredentials` does include `type`); or
- Keep a single helper that emits `{id, transports?}` and let the caller add `type` only for `allowCredentials`.

Prefer the first approach to keep call sites symmetric:

```ruby
def passkey_credential_descriptor(record, kind: :allow)
  descriptor = {id: passkey_credential_id(record)}
  descriptor[:type] = "public-key" if kind == :allow
  transports = (record["transports"] || record[:transports]).to_s.split(",").map(&:strip).reject(&:empty?)
  descriptor[:transports] = transports if transports.any?
  descriptor
end
```

Update both endpoints accordingly: registration uses `kind: :exclude`, authentication uses `kind: :allow`.

- [x] **Step 2: Run the shape tests**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/passkey_test.rb -n /shape|transports/
```

Expected: PASS. Result: `4 runs, 33 assertions, 0 failures, 0 errors, 0 skips`. Existing test `test_option_shapes_include_transport_details_and_per_request_expiration` was updated to drop the `type: "public-key"` assertion from `excludeCredentials` while keeping it on `allowCredentials`.

- [x] **Step 3: Commit**

```bash
git commit -am "fix(passkey): match upstream excludeCredentials shape (no type, omit empty transports)"
```

### Task 4: RP ID Resolution Edge Cases

**Files:**
- Modify: `packages/better_auth-passkey/lib/better_auth/plugins/passkey.rb`

- [x] **Step 1: Replace `passkey_rp_id` with a strict-host implementation**

```ruby
def passkey_rp_id(config, ctx)
  return config[:rp_id] if config[:rp_id]

  base_url = ctx.context.options.base_url.to_s
  return "localhost" if base_url.empty?

  uri = URI.parse(base_url)
  return uri.host || "localhost"
rescue URI::InvalidURIError
  "localhost"
end
```

If `URI.parse` raises on a URL containing whitespace, the rescue keeps the upstream fallback intact. Confirm the upstream `getRpID` only uses `URL.hostname` (no port). Ruby `URI#host` already excludes the port, so this matches upstream.

- [x] **Step 2: Run RP id tests**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/passkey_test.rb -n /rp_id/
```

Expected: PASS. Result: `4 runs, 4 assertions, 0 failures, 0 errors, 0 skips` (`port_stripped`, `invalid_url`, `blank_base_url`, `explicit_config` cases).

- [x] **Step 3: Commit**

```bash
git commit -am "fix(passkey): resolve rp_id host without port and tolerate invalid base URLs"
```

### Task 5: `afterVerification` And `update_passkey` Validation Matrix

**Files:**
- Modify: `packages/better_auth-passkey/lib/better_auth/plugins/passkey.rb`

- [x] **Step 1: Tighten `passkey_after_registration_verification_user_id`**

Replace the validation block with:

```ruby
returned_user_id = result[:user_id]
return target_user_id if returned_user_id.nil? || returned_user_id == ""

unless returned_user_id.is_a?(String) && returned_user_id.length.positive?
  raise APIError.new("BAD_REQUEST", message: PASSKEY_ERROR_CODES.fetch("RESOLVED_USER_INVALID"))
end
```

This explicitly rejects integers, booleans, and other non-string truthy values, matching upstream's `typeof result.userId !== "string" || !result.userId` check.

- [x] **Step 2: Loosen `update_passkey_endpoint` to allow empty string name**

Replace `passkey_require_string!(body, :name)` with a check that allows the empty string:

```ruby
unless body.key?(:name) && body[:name].is_a?(String)
  raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES.fetch("VALIDATION_ERROR"))
end
```

(`""` is still a string and now passes.)

- [x] **Step 3: Run the validation tests**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/passkey_test.rb -n /user_id_matrix|empty_name/
```

Expected: PASS. Result: `5 runs, 8 assertions, 0 failures, 0 errors, 0 skips`. The single matrix scenario was split into four focused tests (`accepts_nil_and_empty_string`, `accepts_non_empty_string`, `rejects_integer`, `rejects_boolean`) plus the `empty_name` test.

- [x] **Step 4: Commit**

```bash
git commit -am "fix(passkey): match upstream userId validation matrix and allow empty update name"
```

### Task 6: Documentation And Final Verification

**Files:**
- Modify: `packages/better_auth-passkey/README.md`
- Modify: `docs/content/docs/plugins/passkey.mdx`

- [x] **Step 1: Update docs**

Documented in `packages/better_auth-passkey/README.md` (new "Upstream parity notes" section) and `docs/content/docs/plugins/passkey.mdx` (new "Upstream Parity Notes" section + tightened `after_verification` semantics paragraph):

- The Ruby plugin omits `type` from `excludeCredentials` to match upstream wire shape; `allowCredentials` still includes `type: "public-key"`.
- The `model_name: "passkeys"` adaptation for SQL adapters (intentional Ruby divergence) and the resulting storage table name.
- The `rp_id` falls back to `URI.parse(base_url).host || "localhost"`, with `localhost` returned on parse failure or empty `base_url`.
- The pre-auth `afterVerification` flow accepts `nil` or `""` as "no override" and rejects every other non-empty-string value with `RESOLVED_USER_INVALID`.
- `update_passkey` accepts empty-string `name`, mirroring upstream's `z.string()`.
- Cross-user `delete_passkey` raises `UNAUTHORIZED` with the `PASSKEY_NOT_FOUND` message.

- [x] **Step 2: Run the full suite**

```bash
cd packages/better_auth-passkey
rbenv exec bundle exec rake test
RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb
```

Expected: tests + lint pass. Result: tests `30 runs, 136 assertions, 0 failures, 0 errors, 0 skips`; standardrb clean (no offenses).

- [x] **Step 3: Run the core session/routes regression**

```bash
cd ../better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/session_test.rb
```

Expected: PASS. Result: `5 runs, 12 assertions, 0 failures, 0 errors, 0 skips`.

- [x] **Step 4: Update the verification log section of this plan with run counts**

- [x] **Step 5: Commit**

```bash
git commit -am "docs(passkey): document upstream parity follow-ups and Ruby adaptations"
```

## Assumptions

- The `webauthn` gem (Ruby) emits `userVerification: "preferred"` by default for `options_for_get`. If a future upgrade changes that, retain Ruby's explicit merge to keep the wire output stable.
- Apps relying on the extra `type` field in `excludeCredentials` will continue to work; browsers default to `public-key` when it is omitted.
- No version bump is part of this plan; if a release is needed, follow the workspace `AGENTS.md` versioning rules.

## Open Questions

- Should the Ruby plugin add an opt-in `legacy_exclude_credential_type: true` switch for apps that depend on the previous shape, or is the wire change safe to ship without a flag?
- Does `BetterAuth::Plugins.passkey` need to expose the `requireResourceOwnership` middleware as a reusable Ruby helper, or is the inline ownership check sufficient for the two endpoints that need it?

## Verification Log

- **Branch:** `feat/passkey-upstream-parity-followup` (based on the same commit as `57904a1` / local `canary` tip when applied in the `nylk` worktree; `canary` ref may be checked out in another worktree).
- **Commits:** Implementation and docs are recorded as `fix(passkey): …` plus `docs(plan): …` in git history (replacing per-task micro-commits from the checklist).
- `packages/better_auth-passkey` test suite: **30 runs, 136 assertions, 0 failures, 0 errors, 0 skips**.
- `packages/better_auth-passkey` standardrb (with `RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache`): clean.
- `packages/better_auth/test/better_auth/session_test.rb`: **5 runs, 12 assertions, 0 failures**.
- Pre-existing helper bug discovered and fixed inline: `BetterAuthPluginsPasskeyTest#build_auth` now defaults `email_and_password: {enabled: true}`, matching the username plugin's helper. Without it, every passkey test that called `sign_up_cookie` errored on `KeyError: key not found: "set-cookie"` because the core `sign_up_email` route now returns `400 Email and password sign up is not enabled` by default.

## Cross-Reference Corrections

While implementing this plan, two upstream behaviors were re-verified against `upstream/packages/passkey/src/routes.ts` (v1.6.9) and `upstream/packages/better-auth/src/api/middlewares/authorization.ts`:

- **Delta #1 (delete ownership)**: Upstream's `requireResourceOwnership` for delete falls through to `throw new APIError(forbiddenStatus)` (no message body) when no `forbiddenError` is provided, not the `notFoundError` message as the original delta description stated. Better-call's default body for an APIError with no message would still serialize to a non-null payload (`{message: "Unauthorized"}` from the status name). The Ruby plugin now emits `{code: "UNAUTHORIZED", message: "Passkey not found"}` to expose a more useful message for clients, which is a Ruby-specific improvement on top of upstream parity.
- **Delta #4 (`userVerification`)**: The `webauthn` Ruby gem's `WebAuthn::Credential.options_for_get` does not emit `userVerification` in its serialized output, so the Ruby plugin still merges `userVerification: "preferred"` into the JSON payload to match upstream's wire shape. The existing test `test_option_shapes_include_transport_details_and_per_request_expiration` covers this.
- **Delta #9 (set_session_cookie ordering)**: Upstream calls `setSessionCookie` before `deleteVerificationByIdentifier`. The Ruby plugin already preserves this ordering and the existing `test_registers_and_authenticates_with_real_webauthn_challenges` test asserts the cookie is set on success, so no additional regression test was added.
