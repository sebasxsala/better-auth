# Social Providers Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port all Better Auth built-in social providers and related social OAuth behavior from upstream `v1.6.9` into the Ruby core gem.

**Architecture:** Keep social provider factories in `packages/better_auth/lib/better_auth/social_providers/`, using a shared provider base for OAuth URL construction, token exchange, refresh, userinfo fetching, profile mapping, and ID-token verification helpers. Provider-specific files should mirror upstream runtime behavior while preserving Ruby's existing hash/callable provider contract used by `/sign-in/social`, `/callback/:providerId`, `/link-social`, and account routes.

**Tech Stack:** Ruby, Minitest, Rack test helpers, `Net::HTTP`, existing BetterAuth crypto/JWT helpers, upstream Better Auth TypeScript source in `upstream/`.

---

## Source Of Truth

- [x] Confirm `upstream/` is initialized only when upstream files are needed.
- [x] Confirm `upstream` is at Better Auth `v1.6.9`: `cd upstream && git rev-parse HEAD` should return `f484269228b7eb8df0e2325e7d264bb8d7796311`.
- [x] Read `packages/better_auth/AGENTS.md` before editing core gem files.
- [x] For each provider, read the matching file in `upstream/packages/core/src/social-providers/`.
- [x] For each behavior change, read the matching upstream tests:
  - `upstream/packages/better-auth/src/social.test.ts`
  - `upstream/packages/better-auth/src/oauth2/link-account.test.ts`
  - `upstream/packages/better-auth/src/api/routes/sign-in.test.ts`
  - `upstream/packages/better-auth/src/api/routes/account.test.ts`
  - `upstream/packages/core/src/oauth2/refresh-access-token.test.ts`
  - `upstream/packages/core/src/oauth2/validate-token.test.ts`

## Phase 1: Shared Provider Runtime

- [x] Extend `packages/better_auth/lib/better_auth/social_providers/base.rb` with upstream-compatible helpers for authorization URLs, PKCE S256, form token exchange, JSON token exchange, bearer GET/POST JSON requests, response status validation, JSON parse failures, and deterministic test endpoint overrides.
- [x] Normalize token payloads into existing Ruby account storage keys: `accessToken`, `refreshToken`, `idToken`, `accessTokenExpiresAt`, `refreshTokenExpiresAt`, `scope`, and `tokenType`.
- [x] Add a shared refresh-token helper matching upstream `refreshAccessToken`, including `expires_in` and `refresh_token_expires_in` handling.
- [x] Add provider option normalization for snake_case and camelCase aliases used by upstream-facing users: `client_id/clientId`, `client_secret/clientSecret`, `scope/scopes`, `disable_default_scope/disableDefaultScope`, `map_profile_to_user/mapProfileToUser`, `get_user_info/getUserInfo`, `verify_id_token/verifyIdToken`, `refresh_access_token/refreshAccessToken`, `disable_id_token_sign_in/disableIdTokenSignIn`, `disable_implicit_sign_up/disableImplicitSignUp`, `disable_sign_up/disableSignUp`.
- [x] Add ID-token verification support where upstream providers expose it, using existing crypto/JWT helpers where possible and injected verifier callbacks where upstream allows override.
- [x] Add focused tests in `packages/better_auth/test/better_auth/social_providers_test.rb` for shared URL encoding, PKCE, token normalization, refresh expiration calculation, HTTP error handling, and option alias normalization.

## Phase 2: Route Parity Before Provider Expansion

- [x] Update `packages/better_auth/lib/better_auth/routes/social.rb` so invalid non-empty signed state fails instead of silently continuing with `{}`.
- [x] Honor `newUserCallbackURL` for newly created social users and `callbackURL` for existing users.
- [x] Enforce trusted URL validation for `callbackURL`, `errorCallbackURL`, and `newUserCallbackURL` in social sign-in/link flows.
- [x] Enforce provider `disableSignUp` separately from `disableImplicitSignUp`.
- [x] Preserve safe `additionalData` in OAuth state while preventing reserved key override.
- [x] Add upstream link-account parity: email verification updates on explicit link, case-insensitive email comparisons, `disableImplicitLinking`, verified-provider implicit linking, and provider-scoped account lookup.
- [x] Add route tests translated from upstream social/link-account/sign-in URL suites in `packages/better_auth/test/better_auth/routes/social_test.rb`.

## Phase 3: Existing Provider Corrections

- [x] `apple`: align scopes, response mode/type, ID-token verification override, refresh support, name extraction from token body/user data, no email fallback for missing name, multi-client-id behavior. Completed with JWKS/max-age ID-token verification, audience/app-bundle audience selection, injected verifier override, token-body names, map-profile override, refresh support, and first-client auth URL behavior.
- [x] `discord`: align scopes, prompt, avatar URL, null-email behavior, map-profile override behavior, token refresh support.
- [x] `github`: align authorization/token/userinfo headers, default scopes, primary email lookup, endpoint overrides for tests, token refresh where upstream supports it.
- [x] `gitlab`: align issuer-derived endpoints, default scopes, inactive-user rejection, profile mapping, token refresh.
- [x] `google`: align multi-client-id behavior, ID-token sign-in verification, hosted-domain/access-type/include-granted-scopes behavior, userinfo fallback, token refresh. Completed with JWKS/max-age ID-token verification, multi-audience validation, id-token-only user info, map-profile override, hosted-domain/access-type/include-granted-scopes, and refresh support.
- [x] `microsoft` / `microsoft_entra_id`: add canonical `microsoft` factory while preserving `microsoft_entra_id`; align tenant issuer checks, public-client support, JWKS verification, ID-token sign-in, `disableIdTokenSignIn`, Graph/userinfo fallback, token refresh. Completed with canonical factory, public client, JWKS/max-age ID-token verification, specific-tenant issuer validation, injected verifier override, `disableIdTokenSignIn`, Graph/id-token fallback, profile-photo data URI support, map-profile override, and Microsoft refresh scope param.

## Phase 4: Missing Built-In Providers

Add one provider file per upstream built-in, require it from `packages/better_auth/lib/better_auth/social_providers.rb`, and add provider-specific tests for URL shape, default scopes, token exchange, userinfo mapping, `map_profile_to_user`, and refresh support where upstream implements it.

- [x] `atlassian`
- [x] `cognito`
- [x] `dropbox`
- [x] `facebook`
- [x] `figma`
- [x] `huggingface`
- [x] `kakao`
- [x] `kick`
- [x] `line`
- [x] `linear`
- [x] `linkedin`
- [x] `naver`
- [x] `notion`
- [x] `paybin`
- [x] `paypal`
- [x] `polar`
- [x] `railway`
- [x] `reddit`
- [x] `roblox`
- [x] `salesforce`
- [x] `slack`
- [x] `spotify`
- [x] `tiktok`
- [x] `twitch`
- [x] `twitter`
- [x] `vercel`
- [x] `vk`
- [x] `wechat`
- [x] `zoom`

## Phase 5: Provider-Specific Upstream Test Translation

- [x] Translate upstream Google multi-client-id tests: wrong audience rejection, first configured client ID in authorization URL, empty array rejection.
- [x] Translate upstream widened multi-client-id tests for Apple, Facebook, and Cognito.
- [x] Translate upstream Apple tests: no email-as-name fallback, first/last name from `token.user`, Apple `idToken` body user name, empty name when no user field exists.
- [x] Translate upstream Vercel tests: provider config, PKCE auth URL, callback creates user, `preferred_username` fallback, additional scopes, `mapProfileToUser`, existing-user callback redirect.
- [x] Translate upstream Microsoft tests: custom `verifyIdToken`, JWKS verification, ID-token sign-in, `disableIdTokenSignIn`, tenant issuer validation, public client without `clientSecret`.
- [x] Translate upstream Railway tests: config, PKCE auth URL, callback creates user/account with `emailVerified: false`.
- [x] Translate upstream providers-without-email tests from `oauth2/link-account.test.ts`, especially Discord null-email with and without synthesized email from `mapProfileToUser`.

## Phase 6: Account Route And Refresh Parity

- [x] Review `packages/better_auth/lib/better_auth/routes/account.rb` against upstream `api/routes/account.test.ts`.
- [x] Ensure built-in providers expose `refresh_access_token` where upstream exposes `refreshAccessToken`.
- [x] Add account-route tests for refreshed `accessToken`, `idToken`, expiration persistence, account lookup by provider account ID, and multiple same-provider accounts.
- [x] Verify account cookie behavior only where already supported by Ruby; document any intentionally out-of-scope upstream client/browser behavior.

## Phase 7: Generic OAuth Provider-Adjacent Parity

- [x] Keep upstream built-in social providers separate from `generic_oauth` helpers.
- [x] Audit helper coverage for `auth0`, `gumroad`, `hubspot`, `keycloak`, `line`, `microsoft-entra-id`, `okta`, `patreon`, and `slack`.
- [x] Add missing Generic OAuth tests for numeric account IDs, async/profile mapping behavior adapted to Ruby callables, duplicate provider ID warnings, RFC 9207 `iss` validation, custom token callbacks, and provider helper URL/user mapping parity.
- [x] Decide explicitly in this plan if Generic OAuth should continue to register only account-route provider hooks in Ruby, or if full `/sign-in/social` registration parity is required. Decision: keep built-in social providers as first-class `/sign-in/social` providers; Generic OAuth continues to expose `/sign-in/oauth2` plus account-route hooks for account info/refresh rather than registering every generic helper into `/sign-in/social`.

## Test Commands

- [x] `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/social_providers_test.rb`
- [x] `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/routes/social_test.rb`
- [x] `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/routes/account_test.rb`
- [x] `cd packages/better_auth && bundle exec ruby -Itest test/better_auth/plugins/generic_oauth_test.rb`
- [x] `cd packages/better_auth && bundle exec rake test`
- [x] `cd packages/better_auth && bundle exec standardrb`

## Verification Notes

- [x] `bundle exec rake test` was rerun outside the sandbox because the suite binds localhost ports and uses local database adapters: `563 runs, 2867 assertions, 0 failures, 0 errors, 0 skips`.
- [x] Residual full-suite blockers were resolved: the device authorization secondary-storage test now enables email/password sign-up before expecting a session cookie, and the delete-user stale-session test now asserts the existing sensitive-session contract (`403 SESSION_NOT_FRESH`).
- [x] Phase 3 was completed after adding JWKS-backed ID-token verification and Microsoft profile-photo/refresh-scope parity. Focused verification: `social_providers_test.rb`, `routes/social_test.rb`, `routes/account_test.rb`, `plugins/oauth_proxy_test.rb`, `plugins/generic_oauth_test.rb`, and `standardrb` all pass.
- [x] Phase 5, Phase 6, and Phase 7 focused gaps were tightened with upstream test translations for widened client ids, Apple/Vercel/Railway, providers without email, same-provider accounts, Generic OAuth numeric IDs, profile mapping callables, duplicate provider warnings, RFC 9207 issuer behavior, helper defaults, and custom token callbacks.

## Acceptance Criteria

- [x] All upstream `v1.6.9` built-in social providers exported from `upstream/packages/core/src/social-providers/index.ts` have Ruby factories.
- [x] Existing Ruby provider factories remain backward compatible.
- [x] The Ruby provider list includes canonical upstream ids, including `microsoft`, and compatibility aliases where Ruby already exposed different names.
- [x] Upstream social provider tests are translated to Ruby or explicitly marked out of scope with a Ruby-specific reason in this plan.
- [x] Tests use local HTTP servers or real in-memory adapter behavior where practical; mocks are limited to external cryptographic/provider verification callbacks that upstream also allows to be injected.
- [x] No Rails dependency is introduced into `packages/better_auth`.
- [x] No package version is bumped as part of this unreleased implementation work.
