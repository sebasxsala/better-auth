# Core OAuth Social Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port Ruby-applicable upstream OAuth2/social-provider tests into `packages/better_auth`.

**Architecture:** Keep provider factories under `SocialProviders`, account/linking route behavior under `Routes::Social` and `Routes::Account`, and token encryption/refresh helper behavior in the existing route/provider helper modules.

**Tech Stack:** Ruby 3.2+, Minitest, memory adapter, injected provider callbacks instead of network mocks unless a local test server is already used.

---

## Audit Summary

Upstream files:

- `oauth2/link-account.test.ts` — 15 titles
- `oauth2/utils.test.ts` — 13 titles
- `social.test.ts` — 40 titles

Existing Ruby targets:

- `routes/social_test.rb` — 22 tests
- `routes/account_test.rb` — 5 tests
- `social_providers_test.rb` — 31 tests
- `plugins/generic_oauth_test.rb` overlaps but belongs to the plugin plan for generic-oauth-specific behavior.

Differences found:

- Ruby has broad social sign-in, callback, link-social, and provider factory coverage, but upstream has more explicit cases for email verification updates during linking, casing callbacks, disabled account linking, and provider trust.
- OAuth token utility coverage is light: upstream tests encrypted token read/migration, raw token compatibility, JWT-looking token passthrough, invalid encrypted value handling, and refresh-token expiry mapping.
- Provider social tests include more per-provider profile mapping, token exchange, scope, PKCE, endpoint override, and implicit-signup behavior than the current single combined Ruby provider matrix.

## Tasks

### Task 1: Link Account Email Verification Matrix

**Files:**
- Modify: `packages/better_auth/test/better_auth/routes/social_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/social.rb`

- [x] Translate link-account cases for provider verified email updating `emailVerified`.
- [x] Add tests for provider unverified email leaving `emailVerified` unchanged.
- [x] Add tests for mismatched email not updating verification.
- [x] Add test for already verified user remaining verified.
- [x] Add test for email casing differences using callback/custom normalization behavior.
- [x] Add tests for disabled account linking and account owned by another user.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/routes/social_test.rb`.

Ruby adaptation notes:

- `Routes::Social.persist_social_user` now updates `emailVerified` after both explicit and implicit account linking when the provider reports a verified matching email.
- Existing linked accounts refresh stored tokens on sign-in by default, and respect `account.update_account_on_sign_in: false`.
- `overrideUserInfoOnSignIn` is translated as `override_user_info_on_sign_in` through normal Ruby option normalization.

### Task 2: OAuth Token Storage And Migration Utilities

**Files:**
- Modify: `packages/better_auth/test/better_auth/routes/account_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/account.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/social.rb`

- [x] Translate token utility cases: empty token passthrough, encryption disabled passthrough, encrypted token decrypt, unencrypted migration passthrough when encryption is enabled, JWT-style token passthrough, invalid encrypted token handling, and refresh-token expiry fields.
- [x] Add tests for stored access/refresh token encryption and decrypted account route responses.
- [x] Add tests for provider refresh callbacks and selected same-provider account lookup.
- [x] Run account and social route tests.

Ruby adaptation notes:

- Ruby symmetric encryption uses the gem's base64url AES-GCM payload, not upstream's hex-looking payload shape, so the storage-format assertion checks round-trip secrecy rather than hex format.
- Refresh routes preserve the existing refresh token, refresh expiry, scope, and id token fallback when the provider omits replacement fields.

### Task 3: Core Social Sign-In And Callback Matrix

**Files:**
- Modify: `packages/better_auth/test/better_auth/routes/social_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/social.rb`

- [x] Translate social sign-in cases for authorization URL, callback state, callback URL validation, new user redirect, existing user redirect, disabled signup, disabled implicit signup, safe additional state, reserved state field protection, POST callback redirect-to-GET, and invalid signed state.
- [x] Translate ID-token sign-in cases for new user creation, existing account reuse, trusted provider linking, untrusted unverified linking rejection, Apple user-name body handling, and Microsoft verifier callback.
- [x] Run social route tests.

### Task 4: Provider Factories And Profile Mapping

**Files:**
- Modify: `packages/better_auth/test/better_auth/social_providers_test.rb`
- Modify provider files under `packages/better_auth/lib/better_auth/social_providers/` only where a translated test fails.

- [x] Translate provider availability cases for all upstream social providers represented in Ruby.
- [x] Translate provider URL/scope/PKCE cases for Google, Apple, GitHub, Discord, Vercel, Railway, WeChat, Microsoft Entra ID, and common OAuth providers already present.
- [x] Translate provider profile mapping and override behavior, including null email handling and avatar/name fallbacks.
- [x] Document provider/client-only or unsupported external-package cases as Ruby exclusions.
- [x] Run social provider tests.

### Task 5: Final Verification

**Files:**
- Modify: `.docs/plans/2026-04-30-core-oauth-social-upstream-parity.md`
- Modify: `.docs/plans/2026-04-29-core-upstream-test-parity.md`

- [x] Mark every OAuth/social upstream title as `Ported`, `Covered by existing Ruby test`, or `Ruby exclusion documented`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec rake test`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec standardrb`.

## OAuth/Social Title Status Matrix

| Upstream file | Upstream title/group | Status | Ruby target / note |
| --- | --- | --- | --- |
| `oauth2/utils.test.ts` | `decryptOAuthToken` empty token, encryption disabled, encrypted token decrypt, unencrypted migration token, JWT-style token, odd-length token | Ported | `routes/account_test.rb` covers Ruby token storage/read helpers. |
| `oauth2/utils.test.ts` | issue #6018 Google access/refresh migration and encrypted-token round trip | Ported | `routes/account_test.rb`; Ruby uses base64url AES-GCM rather than hex output. |
| `oauth2/utils.test.ts` | `setTokenUtil` null/undefined, encryption disabled, encrypted storage, decryptable storage | Ported | `routes/account_test.rb`; `nil` covers TypeScript null/undefined. |
| `oauth2/link-account.test.ts` | verified provider email updates `emailVerified`; unverified provider leaves unchanged; mismatched email leaves unchanged; already verified remains verified | Ported | `routes/social_test.rb`. |
| `oauth2/link-account.test.ts` | case-insensitive account linking through callback and idToken | Ported | `routes/social_test.rb`. |
| `oauth2/link-account.test.ts` | untrusted/unverified linking rejection and verified provider implicit linking | Ported | `routes/social_test.rb`. |
| `oauth2/link-account.test.ts` | `disableImplicitLinking` blocks implicit linking, allows new signup, allows explicit `linkSocial` | Ported | `routes/social_test.rb`. |
| `oauth2/link-account.test.ts` | `overrideUserInfoOnSignIn` updates existing user info | Ported | `routes/social_test.rb` plus `Routes::Social`. |
| `oauth2/link-account.test.ts` | provider-scoped account lookup for same account id across providers | Covered by existing Ruby test | `routes/social_test.rb`. |
| `oauth2/link-account.test.ts` | providers without email: synthesized email via mapProfileToUser and `email_not_found` without mapping | Ported | `social_providers_test.rb` and `routes/social_test.rb`. |
| `social.test.ts` | add providers, social sign-in, callback URL attack protection, new/existing-user redirect behavior | Covered by existing Ruby test | `routes/social_test.rb`. |
| `social.test.ts` | async social provider config | Ruby exclusion documented | Ruby provider config is synchronous callable/hash configuration; no Promise-style provider factory exists. |
| `social.test.ts` | map profile to user and user-info override on sign-in | Ported | `social_providers_test.rb` and `routes/social_test.rb`. |
| `social.test.ts` | refresh access token route and same-provider account lookup | Ported | `routes/account_test.rb`. |
| `social.test.ts` | inferred/custom redirect URI | Covered by existing Ruby test | `routes/social_test.rb` exercises inferred route URI; `social_providers_test.rb` covers provider-level redirect URI overrides. |
| `social.test.ts` | disable implicit signup and disable signup | Covered by existing Ruby test | `routes/social_test.rb`. |
| `social.test.ts` | safe additional OAuth state and reserved state-field protection | Covered by existing Ruby test | `routes/social_test.rb`. |
| `social.test.ts` | `updateAccountOnSignIn: false` | Ported | `routes/social_test.rb` plus `Routes::Social`. |
| `social.test.ts` | Google multiple client IDs and widened Apple/Facebook/Cognito client IDs | Covered by existing Ruby test | `social_providers_test.rb`. |
| `social.test.ts` | Apple name fallback and idToken `user` body behavior | Ported | `social_providers_test.rb` and `routes/social_test.rb`. |
| `social.test.ts` | Vercel config, PKCE, callback create, preferred username fallback, scopes, mapProfileToUser, existing redirect | Covered by existing Ruby test | `social_providers_test.rb` and `routes/social_test.rb`. |
| `social.test.ts` | Microsoft custom verifier, JWKS, id-token sign-in, disabled id-token sign-in, tenant issuer, public client URL | Covered by existing Ruby test | `social_providers_test.rb` and `routes/social_test.rb`; network JWKS is injected as local JWKS data. |
| `social.test.ts` | Railway config, PKCE, callback create | Covered by existing Ruby test | `social_providers_test.rb` and `routes/social_test.rb`. |
