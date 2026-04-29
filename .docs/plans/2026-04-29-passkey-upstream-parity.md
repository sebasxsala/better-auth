# Passkey Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `test-driven-development` for every behavior change. Use `subagent-driven-development` if splitting tasks across workers. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining Better Auth upstream passkey deltas in the Ruby port and make every remaining non-applicable upstream client feature explicit in docs/tests.

**Architecture:** Treat `upstream/packages/passkey` as source of truth for server behavior. Ruby keeps idiomatic `snake_case` API names and the existing `passkeys` SQL table naming unless a test proves wire-level incompatibility. Browser-only `@better-auth/passkey/client` behavior is documented as out of Ruby server scope, not reimplemented as JavaScript inside the gem.

**Tech Stack:** Ruby 3.4.9, Minitest, StandardRB, `webauthn` gem, Better Auth core session/routes.

---

## Summary

Start with tests translated from upstream, watch each fail, implement the minimum fix, then rerun focused tests.

The current branch already contains a large server-parity baseline. The remaining work is to formalize this plan file, finish any unclosed parity gaps, document intentional Ruby adaptations, and verify the full suite.

## Key Changes

- **Server behavior parity:** Keep/finalize registration `attestation: "none"`, discoverable auth without empty `allowCredentials`, validation of passkey request shapes, upstream registration missing-origin error, deep schema merge, ownership checks, `after_verification` user override behavior, and fresh-session enforcement only when upstream requires it.
- **Schema/options policy:** Keep Ruby public options as `snake_case`; accept camelCase input through existing normalization where possible. Preserve `passkeys` SQL table naming as the Ruby adapter convention, and document it as an intentional Ruby adaptation.
- **Client policy:** Do not implement `passkeyClient` in Ruby. Instead, document that Ruby provides the server WebAuthn routes and apps must use browser WebAuthn APIs or their own JS wrapper for `startRegistration`, `startAuthentication`, autofill, and extension result handling.
- **WebAuthn scoped config:** The `webauthn` gem supports `WebAuthn::RelyingParty` per request. The plugin uses that path instead of mutating global `WebAuthn.configuration`.

## Task List

### Task 1: Save Plan And Establish Baseline

- [x] Create `.docs/plans/2026-04-29-passkey-upstream-parity.md` with this plan.
- [x] Run `git status --short --branch` and confirm work is on `codex/passkey-upstream-diff`.
- [x] Run `rbenv exec bundle exec rake test` in `packages/better_auth-passkey`.
- [x] Run `rbenv exec bundle exec ruby -Itest test/better_auth/session_test.rb` in `packages/better_auth`.
- [x] Run StandardRB with `RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache` for touched files.

### Task 2: Lock Server Parity Tests

In `packages/better_auth-passkey/test/better_auth/passkey_test.rb`, ensure tests exist for:

- [x] Registration options include `attestation: "none"`.
- [x] Authentication options omit `allowCredentials` when there is no session/no passkeys.
- [x] Invalid `authenticatorAttachment` returns `VALIDATION_ERROR`.
- [x] Missing `response`, delete `id`, and update `name` return `VALIDATION_ERROR`.
- [x] Missing registration origin returns `FAILED_TO_VERIFY_REGISTRATION`.
- [x] `after_verification` can return a valid `user_id` for pre-auth linking.
- [x] `after_verification` cannot switch users during session-required registration.
- [x] Cross-user update/delete are rejected and do not mutate the target passkey.
- [x] Custom schema overrides deep-merge camelCase built-in fields, e.g. `publicKey`.

Expected red command before fixes:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/passkey_test.rb
```

### Task 3: Finish Server Fixes

In `packages/better_auth-passkey/lib/better_auth/plugins/passkey.rb`:

- [x] Validate query/body shapes before reading values.
- [x] Add `attestation: "none"` to registration option JSON.
- [x] Delete empty `allowCredentials` from auth option JSON.
- [x] Use upstream registration missing-origin error message.
- [x] Use fresh session only when `registration.require_session != false`.
- [x] Deep-merge schemas after normalizing both base and custom hashes.
- [x] Prefix helper names with `passkey_` to avoid collisions in `BetterAuth::Plugins`.

Expected green command:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/passkey_test.rb
```

### Task 4: Core Fresh Session Parity

In `packages/better_auth/test/better_auth/session_test.rb` and `packages/better_auth/lib/better_auth/routes/session.rb`:

- [x] Add a failing test proving `Routes.current_session(ctx, sensitive: true)` rejects stale sessions using `session[:fresh_age]`.
- [x] Implement `SESSION_NOT_FRESH` as `403 FORBIDDEN` when `createdAt` is older than `fresh_age`.
- [x] Preserve `fresh_age: 0` behavior as disabled freshness checks.
- [x] Confirm pre-auth passkey optional session lookup does not require freshness.

Expected commands:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/session_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/passkey_test.rb
```

### Task 5: Documentation And Intentional Adaptations

Update `docs/content/docs/plugins/passkey.mdx` and `packages/better_auth-passkey/README.md`:

- [x] Document all Ruby passkey options: `rp_id`, `rp_name`, `origin`, `authenticator_selection`, `advanced.web_authn_challenge_cookie`, `registration`, `authentication`, `schema`.
- [x] Add pre-auth registration example using `require_session: false`, `resolve_user`, `context`, and `after_verification`.
- [x] Add WebAuthn extensions examples for registration/authentication.
- [x] State that Ruby keeps server routes and wire JSON compatible, while Ruby method/options names are `snake_case`.
- [x] State that browser-only upstream client helpers are not part of the Ruby gem; apps should call WebAuthn browser APIs or their own JS wrapper.

### Task 6: WebAuthn Configuration Risk

- [x] Inspect `webauthn` gem APIs for per-call or scoped configuration support.
- [x] If scoped config exists, add tests for two auth instances with different `rp_id`/`origin`, then remove global request mutation.
- [x] Scoped config exists, so the global-configuration limitation path is not applicable.
- [x] Do not add a flaky thread race test unless the gem gives deterministic hooks.

### Task 7: Final Verification

- [x] Run `rbenv exec bundle exec rake test` in `packages/better_auth-passkey`.
- [x] Run `RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb lib/better_auth/plugins/passkey.rb test/better_auth/passkey_test.rb` in `packages/better_auth-passkey`.
- [x] Run `RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb lib/better_auth/routes/session.rb test/better_auth/session_test.rb` in `packages/better_auth`.
- [x] Run `docker compose up -d` from repo root.
- [x] Run `rbenv exec bundle exec rake test` in `packages/better_auth`.
- [x] Record exact run counts in this plan file before marking complete.

## Assumptions

- “100%” means **100% closure of upstream passkey differences for the Ruby server port**, plus explicit documentation for non-applicable browser client behavior.
- Ruby keeps `snake_case` public APIs and existing `passkeys` storage naming unless a failing compatibility test proves this must change.
- No version bumps or commits are part of this plan unless requested separately.

## Verification Log

- `git status --short --branch`: confirmed `## codex/passkey-upstream-diff`.
- Red check for scoped WebAuthn config: `rbenv exec bundle exec ruby -Itest test/better_auth/passkey_test.rb` failed as expected with global `WebAuthn.configuration.rp_id` mutated to `second.example`.
- `packages/better_auth-passkey`: `rbenv exec bundle exec ruby -Itest test/better_auth/passkey_test.rb` passed with 18 runs, 107 assertions, 0 failures, 0 errors, 0 skips.
- `packages/better_auth-passkey`: `rbenv exec bundle exec rake test` passed with 18 runs, 107 assertions, 0 failures, 0 errors, 0 skips.
- `packages/better_auth-passkey`: `RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb lib/better_auth/plugins/passkey.rb test/better_auth/passkey_test.rb` passed.
- `packages/better_auth`: `rbenv exec bundle exec ruby -Itest test/better_auth/session_test.rb` passed with 5 runs, 12 assertions, 0 failures, 0 errors, 0 skips.
- `packages/better_auth`: `RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb lib/better_auth/routes/session.rb test/better_auth/session_test.rb` passed.
- Repo root: `docker compose up -d` reported postgres, redis, mysql, mongodb, and mssql running.
- `packages/better_auth`: sandboxed `rbenv exec bundle exec rake test` was blocked by local socket/database permissions, then the same command passed outside the sandbox with 479 runs, 2369 assertions, 0 failures, 0 errors, 0 skips.
