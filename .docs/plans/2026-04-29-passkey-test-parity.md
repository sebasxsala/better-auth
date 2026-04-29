# Passkey Upstream Test Parity Plan

**Goal:** Translate the remaining applicable upstream passkey server tests into Ruby before changing implementation.

**Upstream reference:** `upstream/packages/passkey/src/passkey.test.ts` at Better Auth `v1.6.9`.

**Out of scope:** `upstream/packages/passkey/src/client.test.ts` browser client tests and CLI schema snapshot tests.

## Steps

- [x] Add `test_generate_passkey_registration_options_returns_upstream_shape_and_cookie` to `packages/better_auth-passkey/test/better_auth/passkey_test.rb`.
- [x] Add `test_generate_passkey_authentication_options_returns_upstream_shape`.
- [x] Add `test_generate_passkey_authentication_options_without_session_returns_discoverable_shape`.
- [x] Add `test_list_passkeys_returns_upstream_passkey_shape`.
- [x] Add `test_registration_challenge_expiration_is_computed_per_request`.
- [x] Add `test_authentication_challenge_expiration_is_computed_per_request`.
- [x] Add a local `with_time_now` helper in the test file, without adding a dependency.
- [x] Run `cd packages/better_auth-passkey && bundle exec ruby -Itest test/better_auth/passkey_test.rb`.
- [x] If the targeted suite passes, stop without implementation changes.
- [x] If any new parity test fails, make the smallest implementation change in `packages/better_auth-passkey/lib/better_auth/plugins/passkey.rb`. Not needed; all new tests passed.
- [x] Run `cd packages/better_auth-passkey && bundle exec rake test`.
- [x] Optionally run `cd packages/better_auth-passkey && bundle exec rake`.

## Test Translations

- `test_generate_passkey_registration_options_returns_upstream_shape_and_cookie`
  - Upstream: `should generate register options`.
  - Assert response includes `challenge`, `rp`, `user`, `pubKeyCredParams`.
  - Assert `return_headers: true` includes `better-auth-passkey` in `set-cookie`.

- `test_generate_passkey_authentication_options_returns_upstream_shape`
  - Upstream: `should generate authenticate options`.
  - With a signed-in user and an existing passkey, assert response includes `challenge`, `rpId`, `allowCredentials`, `userVerification`.

- `test_generate_passkey_authentication_options_without_session_returns_discoverable_shape`
  - Upstream: `should generate authenticate options without session (discoverable credentials)`.
  - Without session headers, assert response includes `challenge`, `rpId`, `userVerification`, and omits `allowCredentials`.

- `test_list_passkeys_returns_upstream_passkey_shape`
  - Upstream: `should list user passkeys`.
  - Create a passkey including `aaguid`, list as that user, and assert returned item includes `id`, `userId`, `publicKey`, `credentialID`, `aaguid`.

- `test_registration_challenge_expiration_is_computed_per_request`
  - Upstream: `should compute expirationTime per-request, not at init time`.
  - Build auth with `Time.now` stubbed to an init timestamp, advance stubbed time by 6 minutes, generate registration options, then assert latest verification `expiresAt` is greater than the advanced request time.

- `test_authentication_challenge_expiration_is_computed_per_request`
  - Upstream: `should compute expirationTime per-request for authentication options`.
  - Use the same clock-stub pattern, but call `generate_passkey_authentication_options` without a session.

## Verification

- Targeted: `cd packages/better_auth-passkey && bundle exec ruby -Itest test/better_auth/passkey_test.rb`
- Package: `cd packages/better_auth-passkey && bundle exec rake test`
- Optional full package default: `cd packages/better_auth-passkey && bundle exec rake`
