# Passkey Upstream File Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `packages/better_auth-passkey` toward Better Auth upstream `packages/passkey` parity by matching upstream structure, tests, and endpoint behavior nearly file-by-file.

**Architecture:** Keep the Ruby `webauthn` gem as the low-level WebAuthn ceremony engine for registration/authentication option generation and response verification. Better Auth Ruby owns the product/security layers around it: endpoint routing, challenge cookie naming, verification value storage and expiry, session requirements, passkey-first registration, callback contracts, resource ownership, schema metadata, error mapping, and Ruby API shape. Split the current monolithic Ruby plugin into focused modules that mirror upstream concepts while preserving `BetterAuth::Plugins.passkey` as the public entrypoint.

**Tech Stack:** Ruby 3.2+, Minitest, `better_auth`, `better_auth-passkey`, `webauthn`, upstream Better Auth `v1.6.9` TypeScript source under `upstream/packages/passkey/src`.

---

## Scope

- [x] Compare against upstream package version `@better-auth/passkey@1.6.9` from `upstream/packages/passkey/package.json`.
- [x] Confirm no package-level `AGENTS.md` exists for `packages/better_auth-passkey`.
- [x] Preserve public Ruby plugin entrypoint `BetterAuth::Plugins.passkey`.
- [x] Preserve existing Ruby API method names such as `generate_passkey_registration_options`, `verify_passkey_authentication`, `list_passkeys`, `delete_passkey`, and `update_passkey`.
- [x] Preserve endpoint paths from upstream.
- [x] Keep `webauthn` as the low-level WebAuthn dependency.
- [x] Add focused Ruby modules for upstream source areas instead of continuing to grow `lib/better_auth/plugins/passkey.rb`.
- [x] Move broad tests out of the single `passkey_test.rb` only when the move makes upstream parity easier to track.
- [x] Do not add a Ruby browser client unless this package intentionally gains browser-side client support.
- [x] Do not bump gem versions unless this work is explicitly released.

## Upstream Source Checklist

### Package Metadata

- [x] Review `upstream/packages/passkey/package.json` exports, dependencies, version, package scripts, and side-effect metadata.
- [x] Compare to `packages/better_auth-passkey/better_auth-passkey.gemspec`.
- [x] Review `upstream/packages/passkey/README.md` for public API examples.
- [x] Compare to `packages/better_auth-passkey/README.md`.
- [x] Review `upstream/packages/passkey/CHANGELOG.md` for behavioral changes around `v1.6.9`.
- [x] Compare to `packages/better_auth-passkey/CHANGELOG.md`.

### Package Entrypoints

- [x] Port structure for `upstream/packages/passkey/src/index.ts`.
- [x] Preserve Ruby loader `packages/better_auth-passkey/lib/better_auth/passkey.rb`.
- [x] Preserve Ruby version file `packages/better_auth-passkey/lib/better_auth/passkey/version.rb`.
- [x] Keep Ruby entrypoint `packages/better_auth-passkey/lib/better_auth/plugins/passkey.rb` as a thin plugin assembly file after extracting modules.

### Server Source Files

- [x] Port structure for `upstream/packages/passkey/src/error-codes.ts`.
- [x] Port structure for `upstream/packages/passkey/src/schema.ts`.
- [x] Port structure for `upstream/packages/passkey/src/types.ts`.
- [x] Port structure for `upstream/packages/passkey/src/utils.ts`.
- [x] Port structure for `upstream/packages/passkey/src/routes.ts`.
- [x] Port structure for `upstream/packages/passkey/src/version.ts`.

### Client Source Files

- [x] Review `upstream/packages/passkey/src/client.ts`.
- [x] Port server-relevant contracts from `client.ts` into request/response tests where Ruby exposes compatible server behavior.
- [x] Document browser-only client behavior as intentionally not ported unless a Ruby client package is added.
- [x] Review `upstream/packages/passkey/src/client.test.ts`.
- [x] Either create explicit Ruby parity notes for unsupported browser client behavior or add a Ruby helper/client if the package is expected to expose one.

### Build/Test Config Files

- [x] Review `upstream/packages/passkey/vitest.config.ts`.
- [x] Review `upstream/packages/passkey/tsdown.config.ts`.
- [x] Review `upstream/packages/passkey/tsconfig.json`.
- [x] Map only relevant validation expectations to Ruby `Rakefile`, gemspec, Minitest, and StandardRB.

## Ruby Target Structure

### Public Entrypoints

- [x] Keep `packages/better_auth-passkey/lib/better_auth/passkey.rb` as the package loader.
- [x] Keep `packages/better_auth-passkey/lib/better_auth/passkey/version.rb` unchanged unless releasing.
- [x] Reduce `packages/better_auth-passkey/lib/better_auth/plugins/passkey.rb` to plugin assembly and compatibility requires.
- [x] Keep `BetterAuth::Plugins::PASSKEY_ERROR_CODES` available for compatibility if existing users reference it.

### New Ruby Modules Mirroring Upstream

- [x] Create `packages/better_auth-passkey/lib/better_auth/passkey/error_codes.rb` for `PASSKEY_ERROR_CODES`.
- [x] Create `packages/better_auth-passkey/lib/better_auth/passkey/schema.rb` for base passkey schema and custom schema merge.
- [x] Create `packages/better_auth-passkey/lib/better_auth/passkey/types.rb` only if Ruby needs shared structs/value normalization.
- [x] Create `packages/better_auth-passkey/lib/better_auth/passkey/utils.rb` for `rp_id`, origin, relying party, callbacks, and hash normalization helpers.
- [x] Create `packages/better_auth-passkey/lib/better_auth/passkey/challenges.rb` for signed challenge cookie and verification value lifecycle.
- [x] Create `packages/better_auth-passkey/lib/better_auth/passkey/credentials.rb` for credential ID extraction, descriptors, WebAuthn response normalization, and wire shape.
- [x] Create `packages/better_auth-passkey/lib/better_auth/passkey/routes.rb` for route registration and endpoint requires.
- [x] Create `packages/better_auth-passkey/lib/better_auth/passkey/routes/registration.rb` for registration option and registration verification endpoints.
- [x] Create `packages/better_auth-passkey/lib/better_auth/passkey/routes/authentication.rb` for authentication option and authentication verification endpoints.
- [x] Create `packages/better_auth-passkey/lib/better_auth/passkey/routes/management.rb` for list, delete, and update passkey endpoints.

### Ruby Test Targets

- [x] Keep broad existing `packages/better_auth-passkey/test/better_auth/passkey_test.rb` until mirrored tests fully cover it.
- [x] Create `packages/better_auth-passkey/test/better_auth/passkey/index_test.rb`.
- [x] Create `packages/better_auth-passkey/test/better_auth/passkey/error_codes_test.rb`.
- [x] Create `packages/better_auth-passkey/test/better_auth/passkey/schema_test.rb`.
- [x] Create `packages/better_auth-passkey/test/better_auth/passkey/utils_test.rb`.
- [x] Create `packages/better_auth-passkey/test/better_auth/passkey/challenges_test.rb`.
- [x] Create `packages/better_auth-passkey/test/better_auth/passkey/credentials_test.rb`.
- [x] Create `packages/better_auth-passkey/test/better_auth/passkey/routes/registration_test.rb`.
- [x] Create `packages/better_auth-passkey/test/better_auth/passkey/routes/authentication_test.rb`.
- [x] Create `packages/better_auth-passkey/test/better_auth/passkey/routes/management_test.rb`.
- [x] Create `packages/better_auth-passkey/test/better_auth/passkey/client_parity_test.rb` only if browser client behavior gets a Ruby equivalent; otherwise document the intentional gap in this plan.

## Initial File Parity Matrix

| Upstream file | Ruby target | Current Ruby status | Work required |
| --- | --- | --- | --- |
| `upstream/packages/passkey/src/index.ts` | `lib/better_auth/plugins/passkey.rb` | Partial | Entry point exists, but route assembly, schema, errors, utils, and behavior helpers are monolithic. Extract and keep compatibility constants. |
| `upstream/packages/passkey/src/routes.ts` | `lib/better_auth/passkey/routes/*.rb` | Partial | Endpoint behavior mostly exists. Split by registration/authentication/management and add missing edge-case parity tests. |
| `upstream/packages/passkey/src/schema.ts` | `lib/better_auth/passkey/schema.rb` | Partial | Schema exists inline. Extract and verify custom schema merge, model naming, field names, indexes, references, and SQL generation. |
| `upstream/packages/passkey/src/error-codes.ts` | `lib/better_auth/passkey/error_codes.rb` | Covered inline | Extract without changing error messages. Verify all keys remain available through `BetterAuth::Plugins::PASSKEY_ERROR_CODES`. |
| `upstream/packages/passkey/src/types.ts` | `lib/better_auth/passkey/types.rb` or docs/tests | Partial | Ruby has implicit hash contracts. Add tests for callback payload keys and passkey wire shape. Add value objects only if it simplifies behavior. |
| `upstream/packages/passkey/src/utils.ts` | `lib/better_auth/passkey/utils.rb` | Partial | `passkey_rp_id` exists inline. Add direct unit tests matching `getRpID`: explicit `rpID`, base URL hostname, and default `localhost`. |
| `upstream/packages/passkey/src/client.ts` | None yet | Not ported | Browser-only client actions are not represented in Ruby. Document intentional difference or add Ruby client helpers if needed. |
| `upstream/packages/passkey/src/version.ts` | `lib/better_auth/passkey/version.rb` | Ruby-specific | Do not force upstream version into Ruby gem version. Verify plugin exposes package version only if Ruby core expects it. |
| `upstream/packages/passkey/src/passkey.test.ts` | `test/better_auth/passkey_test.rb` plus route tests | Mostly covered | Existing Ruby tests cover many cases, but need mirrored test files and per-case status. |
| `upstream/packages/passkey/src/client.test.ts` | `test/better_auth/passkey/client_parity_test.rb` or docs | Not ported | Mark browser client extension merge and WebAuthn response return behavior as unsupported unless a Ruby client is added. |

## Upstream Test Checklist

### `upstream/packages/passkey/src/passkey.test.ts`

- [x] Port test: `should generate register options`.
- [x] Port test: `should generate register options without session when resolveUser is provided`.
- [x] Port test: `should require resolveUser when session is not available`.
- [x] Port test: `should call afterVerification and allow userId override`.
- [x] Port test: `should reject invalid userId returned from afterVerification`.
- [x] Port test: `should reject afterVerification override that mismatches session user`.
- [x] Port test: `should generate authenticate options`.
- [x] Port test: `should generate authenticate options without session (discoverable credentials)`.
- [x] Port test: `should list user passkeys`.
- [x] Port test: `should update a passkey`.
- [x] Port test: `should not delete a passkey that doesn't exist`.
- [x] Port test: `should delete a passkey`.
- [x] Port test: `should not allow deleting another user's passkey`.
- [x] Port test: `should not allow updating another user's passkey`.
- [x] Port test: `should verify passkey authentication and return user`.
- [x] Port test: `should compute expirationTime per-request, not at init time`.
- [x] Port test: `should compute expirationTime per-request for authentication options`.
- [x] Move or duplicate these covered cases into mirrored Ruby route test files so future agents can see file-level parity without reading the broad legacy test.

### `upstream/packages/passkey/src/client.test.ts`

- [x] Decide whether Ruby should expose a passkey client equivalent.
- [x] If no Ruby client is planned, document `merges registration extensions and returns WebAuthn response` as intentionally browser-client-only.
- [x] If no Ruby client is planned, document `merges authentication extensions and returns WebAuthn response` as intentionally browser-client-only.
- [x] If Ruby client helpers are added, port test: `merges registration extensions and returns WebAuthn response`.
- [x] If Ruby client helpers are added, port test: `merges authentication extensions and returns WebAuthn response`.

## Existing Ruby Test Checklist

### `packages/better_auth-passkey/test/better_auth/passkey_test.rb`

- [x] Preserve `test_generate_passkey_registration_options_returns_upstream_shape_and_cookie`.
- [x] Preserve `test_generate_passkey_authentication_options_returns_upstream_shape`.
- [x] Preserve `test_generate_passkey_authentication_options_without_session_returns_discoverable_shape`.
- [x] Preserve `test_list_passkeys_returns_upstream_passkey_shape`.
- [x] Preserve `test_registration_challenge_expiration_is_computed_per_request`.
- [x] Preserve `test_authentication_challenge_expiration_is_computed_per_request`.
- [x] Preserve `test_registers_and_authenticates_with_real_webauthn_challenges`.
- [x] Preserve `test_passkey_first_registration_resolves_user_context_extensions_and_callback`.
- [x] Preserve `test_passkey_first_registration_requires_resolver_and_valid_user`.
- [x] Preserve `test_passkey_first_registration_rejects_invalid_after_verification_user_id`.
- [x] Preserve `test_passkey_first_registration_allows_after_verification_user_id_override`.
- [x] Preserve `test_passkey_first_registration_with_optional_stale_session_does_not_require_fresh_session`.
- [x] Preserve `test_session_registration_rejects_after_verification_user_id_mismatch`.
- [x] Preserve `test_authentication_extensions_callback_and_array_origin`.
- [x] Preserve `test_lists_updates_and_deletes_only_the_current_users_passkeys`.
- [x] Preserve `test_option_shapes_include_transport_details_and_per_request_expiration`.
- [x] Preserve `test_custom_schema_deep_merges_with_base_passkey_schema`.
- [x] Preserve `test_passkey_uses_scoped_webauthn_relying_party_per_auth_instance`.
- [x] Preserve `test_update_passkey_requires_name`.
- [x] Preserve `test_validates_passkey_request_shapes`.
- [x] Preserve `test_sql_schema_includes_passkey_table`.
- [x] Preserve `test_rejects_expired_challenge_and_delete_not_found_message`.
- [x] Preserve `test_rejects_missing_challenge_and_wrong_registration_user`.
- [x] Preserve `test_delete_passkey_for_another_user_returns_not_found_message`.
- [x] Preserve `test_register_options_exclude_credentials_match_upstream_shape`.
- [x] Preserve `test_register_options_omit_transports_when_passkey_has_none`.
- [x] Preserve `test_rp_id_falls_back_to_hostname_with_port_stripped`.
- [x] Preserve `test_rp_id_returns_localhost_when_base_url_is_invalid`.
- [x] Preserve `test_rp_id_returns_localhost_when_base_url_is_blank`.
- [x] Preserve `test_rp_id_explicit_config_takes_precedence_over_base_url`.
- [x] Preserve `test_after_verification_user_id_matrix_accepts_nil_and_empty_string`.
- [x] Preserve `test_after_verification_user_id_matrix_accepts_non_empty_string`.
- [x] Preserve `test_after_verification_user_id_matrix_rejects_integer`.
- [x] Preserve `test_after_verification_user_id_matrix_rejects_boolean`.
- [x] Preserve `test_update_passkey_allows_empty_name_to_match_upstream`.
- [x] Preserve `test_registration_missing_origin_uses_failed_registration_error`.
- [x] Rehome tests into mirrored files or leave this file as a compatibility integration suite after new mirrored tests exist.

## Function and Behavior Parity Checklist

### `index.ts` / Plugin Assembly

- [x] Match upstream plugin `id: "passkey"`.
- [x] Match upstream endpoint names and endpoint paths.
- [x] Match upstream default option `origin: nil`.
- [x] Match upstream advanced default challenge cookie name `better-auth-passkey`.
- [x] Match upstream challenge max age of 5 minutes.
- [x] Merge custom schema with base passkey schema.
- [x] Expose `PASSKEY_ERROR_CODES`.
- [x] Keep original options/config available in plugin metadata.
- [x] Verify Ruby plugin version behavior is intentionally Ruby-gem-specific.

### `error-codes.ts`

- [x] Include `CHALLENGE_NOT_FOUND`.
- [x] Include `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY`.
- [x] Include `FAILED_TO_VERIFY_REGISTRATION`.
- [x] Include `PASSKEY_NOT_FOUND`.
- [x] Include `AUTHENTICATION_FAILED`.
- [x] Include `UNABLE_TO_CREATE_SESSION`.
- [x] Include `FAILED_TO_UPDATE_PASSKEY`.
- [x] Include `PREVIOUSLY_REGISTERED`.
- [x] Include `REGISTRATION_CANCELLED`.
- [x] Include `AUTH_CANCELLED`.
- [x] Include `UNKNOWN_ERROR`.
- [x] Include `SESSION_REQUIRED`.
- [x] Include `RESOLVE_USER_REQUIRED`.
- [x] Include `RESOLVED_USER_INVALID`.
- [x] Add direct tests that every upstream error key and message exists in Ruby.

### `schema.ts`

- [x] Keep `passkey.name` optional string.
- [x] Keep `passkey.publicKey` required string.
- [x] Keep `passkey.userId` required string with reference to `user.id` and index.
- [x] Keep `passkey.credentialID` required string with index.
- [x] Keep `passkey.counter` required number.
- [x] Keep `passkey.deviceType` required string.
- [x] Keep `passkey.backedUp` required boolean.
- [x] Keep `passkey.transports` optional string.
- [x] Keep `passkey.createdAt` optional date.
- [x] Keep `passkey.aaguid` optional string.
- [x] Verify Ruby DB adapter maps camelCase schema fields to expected SQL columns such as `credential_id`.
- [x] Verify custom schema deep merge keeps unspecified base field metadata.

### `types.ts`

- [x] Document Ruby equivalent of `WebAuthnChallengeValue`: `expectedChallenge`, `userData.id`, optional `userData.name`, optional `userData.displayName`, optional `context`.
- [x] Document Ruby equivalent of `PasskeyRegistrationUser`: `id`, `name`, optional `display_name`/`displayName`.
- [x] Document Ruby registration options: `require_session`, `resolve_user`, `after_verification`, `extensions`.
- [x] Document Ruby authentication options: `extensions`, `after_verification`.
- [x] Add tests for callback payload keys passed to `resolve_user`.
- [x] Add tests for callback payload keys passed to registration `after_verification`.
- [x] Add tests for callback payload keys passed to authentication `after_verification`.
- [x] Add tests for passkey wire shape returned by create/list/update/auth flows.

### `utils.ts` / `getRpID`

- [x] Return explicit `rp_id` when configured.
- [x] Return hostname from `base_url` with port stripped.
- [x] Return `localhost` when base URL is blank or invalid in Ruby.
- [x] Add direct unit test matching upstream default: no `rp_id` and no base URL returns `localhost`.
- [x] Verify intentional difference: upstream `new URL(baseURL)` raises on invalid URL, while Ruby currently falls back to `localhost`.
- [x] Record any chosen Ruby-specific invalid URL behavior in this plan when implemented.

### `routes.ts` / `resolveExtensions`

- [x] Support static registration extensions.
- [x] Support callable registration extensions receiving `ctx`.
- [x] Support static authentication extensions.
- [x] Support callable authentication extensions receiving `ctx`.
- [x] Verify nil/absent extensions are omitted or serialized compatibly with upstream.
- [x] Add focused tests in route-specific files instead of only broad integration tests.

### `routes.ts` / `resolveRegistrationUser`

- [x] Default `registration.requireSession` to true.
- [x] Require fresh session for default registration option generation.
- [x] Use session user id for registration user id.
- [x] Use session email or id for registration user name/display name.
- [x] Allow `registration.requireSession: false`.
- [x] Use existing session when `requireSession: false` and a session is available.
- [x] Require `resolve_user` when `requireSession: false` and no session exists.
- [x] Reject resolved user without id or name.
- [x] Add explicit test for upstream error code `SESSION_REQUIRED` when default registration lacks a session.
- [x] Verify Ruby fresh-session middleware behavior matches upstream `freshSessionMiddleware`.

### `generatePasskeyRegistrationOptions`

- [x] Endpoint path is `GET /passkey/generate-register-options`.
- [x] Validate query `authenticatorAttachment` as `platform` or `cross-platform`.
- [x] Accept optional query `name`.
- [x] Accept optional query `context`.
- [x] Find existing passkeys for the target user.
- [x] Build RP name from `rp_name` or app name.
- [x] Build RP ID from explicit `rp_id` or base URL hostname.
- [x] Use query name before resolved user name for WebAuthn user name.
- [x] Set attestation to `none`.
- [x] Build `excludeCredentials` from existing credential IDs.
- [x] Omit `type` from registration `excludeCredentials`, matching upstream SimpleWebAuthn output.
- [x] Include transports in `excludeCredentials` only when present.
- [x] Merge configured authenticator selection and query authenticator attachment.
- [x] Default resident key to `preferred`.
- [x] Default user verification to `preferred`.
- [x] Include registration extensions.
- [x] Set signed challenge cookie using configured cookie name.
- [x] Store verification value keyed by random token.
- [x] Store `expectedChallenge`.
- [x] Store `userData`.
- [x] Store passkey-first `context`.
- [x] Compute `expiresAt` per request, not at plugin initialization.
- [x] Verify generated user ID entropy and encoding are acceptable Ruby adaptation of upstream `TextEncoder(generateRandomString(32, "a-z", "0-9"))`.

### `generatePasskeyAuthenticationOptions`

- [x] Endpoint path is `GET /passkey/generate-authenticate-options`.
- [x] Allow no session for discoverable credential sign-in.
- [x] When session exists, find passkeys for session user.
- [x] Include `allowCredentials` only when the session user has passkeys.
- [x] Include transports in `allowCredentials` only when present.
- [x] Set `userVerification` to `preferred`.
- [x] Include authentication extensions.
- [x] Set signed challenge cookie using configured cookie name.
- [x] Store `expectedChallenge`.
- [x] Store `userData.id` as session user id or empty string.
- [x] Compute `expiresAt` per request.
- [x] Add direct test that no-session authentication stores empty `userData.id`.

### `verifyPasskeyRegistration`

- [x] Endpoint path is `POST /passkey/verify-registration`.
- [x] Require request body `response`.
- [x] Accept optional body `name`.
- [x] Use configured `origin` or request `Origin` header.
- [x] Return `FAILED_TO_VERIFY_REGISTRATION` when origin is missing.
- [x] Read signed challenge cookie from configured cookie name.
- [x] Return `CHALLENGE_NOT_FOUND` when cookie is missing.
- [x] Return `CHALLENGE_NOT_FOUND` when verification value is missing or expired.
- [x] Parse stored challenge JSON.
- [x] Reject session user mismatch with `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY`.
- [x] Verify WebAuthn registration response with expected challenge, origin, RP ID, and no required user verification.
- [x] Call registration `after_verification`.
- [x] Pass callback context from stored challenge.
- [x] Allow callback to override target `user_id` with a non-empty string.
- [x] Treat nil or empty callback `user_id` as no override in Ruby.
- [x] Reject non-string callback `user_id` with `RESOLVED_USER_INVALID`.
- [x] Reject callback user override that mismatches authenticated session user.
- [x] Store credential public key as strict base64.
- [x] Store credential ID.
- [x] Store counter.
- [x] Store device type.
- [x] Store backup status.
- [x] Store transports as comma-separated string.
- [x] Store created timestamp.
- [x] Store AAGUID where available.
- [x] Delete verification value after successful registration.
- [x] Compare error mapping for unexpected registration verification failures: upstream catches and returns `INTERNAL_SERVER_ERROR`; Ruby intentionally keeps explicit callback validation errors instead of remapping them.

### `verifyPasskeyAuthentication`

- [x] Endpoint path is `POST /passkey/verify-authentication`.
- [x] Require request body `response`.
- [x] Use configured `origin` or request `Origin` header.
- [x] Return `origin missing` bad request when origin is missing.
- [x] Read signed challenge cookie from configured cookie name.
- [x] Return `CHALLENGE_NOT_FOUND` when cookie is missing.
- [x] Return `CHALLENGE_NOT_FOUND` when verification value is missing or expired.
- [x] Find passkey by response credential ID.
- [x] Return `PASSKEY_NOT_FOUND` with unauthorized status when credential is missing.
- [x] Verify WebAuthn authentication response with expected challenge, origin, RP ID, public key, counter, transports, and no required user verification.
- [x] Call authentication `after_verification`.
- [x] Update stored counter to new sign count.
- [x] Create session for passkey user.
- [x] Return `UNABLE_TO_CREATE_SESSION` if session creation fails.
- [x] Load passkey user.
- [x] Set session cookie.
- [x] Delete verification value after successful authentication.
- [x] Return response object with `session` and `user`.
- [x] Compare error mapping for unexpected authentication failures: upstream returns `BAD_REQUEST` with `AUTHENTICATION_FAILED`.

### Management Routes

- [x] `listPasskeys`: endpoint path is `GET /passkey/list-user-passkeys`.
- [x] `listPasskeys`: require authenticated session.
- [x] `listPasskeys`: return only current user's passkeys.
- [x] `deletePasskey`: endpoint path is `POST /passkey/delete-passkey`.
- [x] `deletePasskey`: require authenticated session.
- [x] `deletePasskey`: require body `id`.
- [x] `deletePasskey`: reject missing passkey with `PASSKEY_NOT_FOUND`.
- [x] `deletePasskey`: reject another user's passkey with unauthorized status and upstream-compatible message.
- [x] `deletePasskey`: delete owned passkey and return `{status: true}`.
- [x] `updatePasskey`: endpoint path is `POST /passkey/update-passkey`.
- [x] `updatePasskey`: require authenticated session.
- [x] `updatePasskey`: require body `id`.
- [x] `updatePasskey`: require body `name` as a string.
- [x] `updatePasskey`: allow empty string name to match upstream `z.string()`.
- [x] `updatePasskey`: reject another user's passkey with unauthorized status and `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY`.
- [x] `updatePasskey`: return `{passkey: updatedPasskey}`.
- [x] Add focused route tests for each ownership behavior after extracting route modules.

### `client.ts` / Browser Client Behavior

- [x] Decide whether Ruby package is server-only.
- [x] If server-only, document no Ruby equivalent for `passkeyClient()`.
- [x] If server-only, document no Ruby equivalent for `getPasskeyActions()`.
- [x] If server-only, document no Ruby equivalent for `startRegistration`, `startAuthentication`, browser autofill, auto-register, WebAuthn browser error mapping, nanostore atoms, or client atom listeners.
- [x] Ensure server responses contain the fields the upstream browser client expects: registration options, authentication options, passkey create response, auth session response, update/delete/list response shapes.

## Initial Test Parity Matrix

| Upstream test file | Upstream `it` count | Ruby target | Ruby status | Notes |
| --- | ---: | --- | --- | --- |
| `upstream/packages/passkey/src/passkey.test.ts` | 17 | `packages/better_auth-passkey/test/better_auth/passkey_test.rb` and new route tests | Mostly covered | Existing Ruby suite has 36 tests, including real `webauthn` ceremonies and upstream security/ownership cases. Needs mirrored split for maintainability. |
| `upstream/packages/passkey/src/client.test.ts` | 2 | `packages/better_auth-passkey/test/better_auth/passkey/client_parity_test.rb` or parity notes | Not ported | Upstream tests browser client extension merging and WebAuthn response return payloads. Ruby currently has no browser client layer. |

## Ruby-Specific Adaptations to Review

- [x] Ruby uses `webauthn` gem instead of `@simplewebauthn/server`; keep this as the engine boundary.
- [x] Ruby tests use `WebAuthn::FakeClient` for real ceremonies; keep behavior-focused coverage instead of mocking verification unless a dependency is impractical.
- [x] Ruby option keys are snake_case (`rp_id`, `rp_name`, `require_session`, `resolve_user`, `after_verification`, `web_authn_challenge_cookie`) while upstream TypeScript uses camelCase.
- [x] Ruby response payloads mix symbol keys in direct API calls and JSON string keys in response bodies; add assertions only where the public Ruby API promises that shape.
- [x] Ruby currently treats invalid `base_url` as `localhost`; upstream `getRpID` only handles valid `new URL(baseURL)`. Decide and document whether the Ruby fallback stays.
- [x] Ruby currently keeps passkey schema model name as `passkeys`; verify this is the desired Ruby DB table adaptation even though upstream model key is `passkey`.
- [x] Ruby has extra tests for stale optional sessions, scoped relying parties, request validation, SQL schema, missing origin, and after-verification matrix; preserve them as Ruby hardening tests.

## Execution Order

### Phase 1: Inventory and Plan Updates

- [x] Inventory upstream files under `upstream/packages/passkey`.
- [x] Inventory Ruby files under `packages/better_auth-passkey`.
- [x] Count upstream passkey server tests.
- [x] Count upstream passkey client tests.
- [x] Count current Ruby passkey tests.
- [x] Create this file-level parity plan.
- [ ] Commit only the plan.

### Phase 2: Extract Constants, Schema, Utils, and Challenge Helpers

- [x] Create `lib/better_auth/passkey/error_codes.rb`.
- [x] Move `PASSKEY_ERROR_CODES` out of `plugins/passkey.rb`.
- [x] Add `test/better_auth/passkey/error_codes_test.rb`.
- [x] Run `rbenv exec bundle exec ruby -Itest packages/better_auth-passkey/test/better_auth/passkey/error_codes_test.rb`.
- [x] Create `lib/better_auth/passkey/schema.rb`.
- [x] Move `passkey_schema` and schema merge helper out of `plugins/passkey.rb`.
- [x] Add `test/better_auth/passkey/schema_test.rb`.
- [x] Run the schema test file.
- [x] Create `lib/better_auth/passkey/utils.rb`.
- [x] Move RP/origin/relying-party/callback helpers out of `plugins/passkey.rb`.
- [x] Add `test/better_auth/passkey/utils_test.rb`.
- [x] Run the utils test file.
- [x] Create `lib/better_auth/passkey/challenges.rb`.
- [x] Move challenge cookie, challenge storage, challenge lookup, and expiry handling out of `plugins/passkey.rb`.
- [x] Add `test/better_auth/passkey/challenges_test.rb`.
- [x] Run the challenges test file.
- [x] Run `rbenv exec bundle exec ruby -Itest packages/better_auth-passkey/test/better_auth/passkey_test.rb`.
- [ ] Commit extraction with passing focused tests.

### Phase 3: Extract Credential Normalization and Route Modules

- [x] Create `lib/better_auth/passkey/credentials.rb`.
- [x] Move `passkey_webauthn_response`, `passkey_attestation_response`, `passkey_authenticator_data`, `passkey_wire`, `passkey_credential_id`, and `passkey_credential_descriptor`.
- [x] Add `test/better_auth/passkey/credentials_test.rb`.
- [x] Run the credentials test file.
- [x] Create `lib/better_auth/passkey/routes.rb`.
- [x] Create `lib/better_auth/passkey/routes/registration.rb`.
- [x] Move registration option and verification endpoints.
- [x] Create `lib/better_auth/passkey/routes/authentication.rb`.
- [x] Move authentication option and verification endpoints.
- [x] Create `lib/better_auth/passkey/routes/management.rb`.
- [x] Move list, delete, and update endpoints.
- [x] Keep `plugins/passkey.rb` assembling the plugin endpoints.
- [x] Run the legacy passkey test file.
- [ ] Commit route extraction with passing tests.

### Phase 4: Mirror Upstream Tests by Area

- [x] Move or duplicate registration option tests into `test/better_auth/passkey/routes/registration_test.rb`.
- [x] Move or duplicate registration verification tests into `test/better_auth/passkey/routes/registration_test.rb`.
- [x] Move or duplicate authentication option tests into `test/better_auth/passkey/routes/authentication_test.rb`.
- [x] Move or duplicate authentication verification tests into `test/better_auth/passkey/routes/authentication_test.rb`.
- [x] Move or duplicate list/update/delete tests into `test/better_auth/passkey/routes/management_test.rb`.
- [x] Keep broad real-ceremony integration test in `passkey_test.rb` until route tests prove equivalent behavior.
- [x] Mark each upstream `passkey.test.ts` case as `covered`, `partial`, `not ported`, or `intentionally different` in this plan.
- [ ] Commit test mirror updates separately from behavior changes.

### Phase 5: Client Parity Decision

- [x] Decide whether `better_auth-passkey` should stay server-only.
- [x] If server-only, add a short section to README documenting that upstream browser `passkeyClient()` is not part of this Ruby gem.
- [x] If server-only, mark `client.test.ts` cases as intentionally different in this plan.
- [x] If adding a Ruby client helper, create implementation and tests before changing docs.
- [ ] Commit client parity documentation or implementation separately.

### Phase 6: Behavior Gap Closure

- [x] Add missing direct test for `SESSION_REQUIRED` on default registration without a session.
- [x] Add missing direct test for no-session authentication challenge `userData.id` being empty.
- [x] Add missing direct test for nil extensions being omitted or serialized compatibly.
- [x] Add missing direct test for all upstream error keys and messages.
- [x] Add missing direct tests for callback payload keys.
- [x] Review invalid base URL behavior and document Ruby-specific choice.
- [x] Review unexpected WebAuthn verification error mapping against upstream.
- [x] Implement only behavior needed to make new parity tests pass.
- [x] Update this plan when a behavior is covered or intentionally different.
- [ ] Commit behavior changes by upstream module area.

### Phase 7: Final Verification

- [x] Run `rbenv exec bundle exec ruby -Itest packages/better_auth-passkey/test/better_auth/passkey_test.rb`.
- [x] Run every new `packages/better_auth-passkey/test/better_auth/passkey/**/*_test.rb` file.
- [x] Run `rbenv exec bundle exec rake test`.
- [x] Run `rbenv exec bundle exec standardrb`.
- [x] Confirm this plan has no unchecked upstream source files that were skipped without notes.
- [x] Confirm this plan has no unchecked upstream tests that were skipped without notes.
- [ ] Commit final plan updates and cleanup.

## Commit Strategy

- [ ] Commit this plan separately from code.
- [ ] Commit module extraction separately from behavior changes.
- [ ] Commit mirrored tests before implementation fixes when practical.
- [ ] Commit route behavior by upstream endpoint area.
- [ ] Commit client parity documentation separately from server behavior.
- [x] Do not include unrelated dirty worktree changes.
