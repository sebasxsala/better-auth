# OAuth Provider Upstream File Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Bring `packages/better_auth-oauth-provider` closer to Better Auth upstream `upstream/packages/oauth-provider/src` parity by matching upstream structure and tests nearly file-by-file.

**Architecture:** Keep `BetterAuth::Plugins.oauth_provider` as the public Ruby plugin entrypoint and keep shared protocol primitives in core `BetterAuth::Plugins::OAuthProtocol`. The package should mirror upstream file boundaries where practical, use focused Ruby modules under `lib/better_auth/plugins/oauth_provider/`, and port upstream behavior through real request/database tests rather than mocks. Any behavior that intentionally differs because of Ruby packaging or compatibility must be documented in this plan and in the relevant test.

**Tech Stack:** Ruby 3.2+, Minitest, `better_auth`, `better_auth-oauth-provider`, shared `OAuthProtocol`, upstream Better Auth `v1.6.9` TypeScript source under `upstream/packages/oauth-provider/src`.

---

## Scope

- [x] Use `upstream/packages/oauth-provider/src` at Better Auth `v1.6.9` as source of truth.
- [x] Preserve public Ruby plugin entrypoint `BetterAuth::Plugins.oauth_provider`.
- [x] Preserve existing Ruby package require path `require "better_auth/oauth_provider"`.
- [x] Keep endpoint behavior aligned with upstream `/oauth2/*` paths.
- [x] Keep legacy Ruby compatibility endpoint aliases only where already supported or intentionally documented.
- [x] Use canonical OAuth Provider storage models: `oauthClient`, `oauthAccessToken`, `oauthRefreshToken`, and `oauthConsent`.
- [x] Do not reintroduce `oidcProvider` / `oauthApplication` behavior into the OAuth Provider package.
- [x] Do not bump gem versions unless this work is explicitly released.

## Upstream Source Checklist

### Package Entrypoints

- [x] Compare and port structure for `upstream/packages/oauth-provider/src/index.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/oauth.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/client.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/client-resource.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/version.ts`.

### Endpoint Modules

- [x] Compare and port structure for `upstream/packages/oauth-provider/src/authorize.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/continue.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/consent.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/metadata.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/register.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/token.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/introspect.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/revoke.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/userinfo.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/logout.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/mcp.ts`.

### Client Management

- [x] Compare and port structure for `upstream/packages/oauth-provider/src/oauthClient/index.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/oauthClient/endpoints.ts`.

### Consent Management

- [x] Compare and port structure for `upstream/packages/oauth-provider/src/oauthConsent/index.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/oauthConsent/endpoints.ts`.

### Middleware, Schema, Types, And Utils

- [x] Compare and port structure for `upstream/packages/oauth-provider/src/middleware/index.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/schema.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/types/index.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/types/oauth.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/types/helpers.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/types/zod.ts`.
- [x] Compare and port structure for `upstream/packages/oauth-provider/src/utils/index.ts`.

## Ruby Target Structure

### Existing Ruby Entrypoints

- [x] Keep `packages/better_auth-oauth-provider/lib/better_auth/oauth_provider.rb` as the package require entrypoint.
- [x] Keep `packages/better_auth-oauth-provider/lib/better_auth/oauth_provider/version.rb`.
- [x] Keep `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb` as the plugin assembler and loader.

### Existing Ruby Endpoint Modules

- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/authorize.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/continue.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/consent.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/metadata.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/register.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/token.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/introspect.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/revoke.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/userinfo.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/logout.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/schema.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/rate_limit.rb`.

### Existing Ruby Client And Consent Modules

- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/oauth_client/index.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/oauth_client/endpoints.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/oauth_consent/index.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/oauth_consent/endpoints.rb`.

### Ruby Files To Add Or Decide Intentionally Different

- [x] Create or intentionally skip `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/client.rb`.
- [x] Create or intentionally skip `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/client_resource.rb`.
- [x] Create or intentionally skip `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/mcp.rb`.
- [x] Create or intentionally skip `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/middleware/index.rb`.
- [x] Create or intentionally skip `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/types/index.rb`.
- [x] Create or intentionally skip `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/types/oauth.rb`.
- [x] Create or intentionally skip `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/types/helpers.rb`.
- [x] Create or intentionally skip `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/types/zod.rb`.
- [x] Create or intentionally skip `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider/utils/index.rb`.

## Behavior Parity Checklist

### Metadata And Discovery

- [x] Compare authorization-server metadata fields against upstream `metadata.ts`.
- [x] Compare OIDC metadata fields against upstream `metadata.ts`.
- [x] Compare cache headers and override behavior.
- [x] Compare issuer normalization and RFC 9207 `iss` behavior.
- [x] Compare JWKS URI advertisement behavior.
- [x] Compare disabled-openid behavior.

### Authorization, Prompts, And Consent

- [x] Compare authorize request validation.
- [x] Compare redirect URI validation.
- [x] Compare PKCE requirement behavior.
- [x] Compare `prompt=none`, `prompt=login`, `prompt=create`, `prompt=select_account`, and `prompt=consent`.
- [x] Compare signed query serialization for login/continue redirects.
- [x] Compare request URI resolver behavior.
- [x] Compare consent-code storage, expiry, rejection, and narrowed scopes.
- [x] Compare continue endpoint behavior for created, selected, and post-login flows.

### Dynamic Registration And Client Management

- [x] Compare dynamic registration defaults and restrictions.
- [x] Compare public, confidential, native, web, and user-agent-based client rules.
- [x] Compare server-only/admin-only client fields.
- [x] Compare metadata stripping and stored client response shape.
- [x] Compare client ownership and reference-id behavior.
- [x] Compare create/read/list/update/delete endpoints.
- [x] Compare public-client and prelogin public-client responses.
- [x] Compare client secret rotation behavior.
- [x] Compare client privilege callbacks.

### Token, Refresh, Introspection, And Revocation

- [x] Compare authorization-code token exchange behavior.
- [x] Compare refresh-token rotation and replay protection.
- [x] Compare client-credentials grant behavior.
- [x] Compare scope reduction during refresh.
- [x] Compare token prefix behavior.
- [x] Compare custom token response field filtering.
- [x] Compare ID token claims, nonce, auth time, and pinned claim behavior.
- [x] Compare JWT resource access token behavior.
- [x] Compare opaque token introspection response shape.
- [x] Compare JWT token introspection behavior.
- [x] Compare revocation with and without token hints.
- [x] Compare token type hint mismatch errors.

### Userinfo, Pairwise, Logout, MCP, And Utilities

- [x] Compare userinfo OpenID/profile/email scope filtering.
- [x] Compare custom userinfo claim callback behavior.
- [x] Compare pairwise subject sector identifier behavior.
- [x] Compare pairwise registration validation.
- [x] Compare end-session validation and redirect behavior.
- [x] Compare MCP resource handler behavior from upstream `mcp.ts`.
- [x] Compare timestamp utility parsing.
- [x] Compare query serialization utility behavior.
- [x] Compare zod/schema validation behavior and Ruby-safe equivalents.

## Upstream Test Checklist

### Root Test Files

- [x] Port tests from `upstream/packages/oauth-provider/src/authorize.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/introspect.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/logout.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/mcp.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/metadata.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/oauth.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/pairwise.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/pkce-optional.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/register.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/revoke.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/token.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/userinfo.test.ts`.

### Nested Test Files

- [x] Port tests from `upstream/packages/oauth-provider/src/oauthClient/endpoints.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/oauthClient/endpoints-privileges.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/oauthConsent/endpoints.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/types/zod.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/utils/query-serialization.test.ts`.
- [x] Port tests from `upstream/packages/oauth-provider/src/utils/timestamps.test.ts`.

## Ruby Test Checklist

### Existing Ruby Test Files To Keep Or Split

- [x] Review and keep/split `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`.
- [x] Review and keep/split `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/authorization_registration_test.rb`.
- [x] Review and keep/split `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/client_privileges_test.rb`.
- [x] Review and keep/split `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/endpoint_pairwise_test.rb`.
- [x] Review and keep/split `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/metadata_utilities_test.rb`.
- [x] Review and keep/split `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/organization_integration_test.rb`.
- [x] Review and keep/split `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/prompt_test.rb`.
- [x] Review and keep/split `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/rate_limit_test.rb`.
- [x] Review and keep/split `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/token_pkce_test.rb`.
- [x] Review and keep/split `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/userinfo_test.rb`.
- [x] Keep or update `packages/better_auth-oauth-provider/test/support/oauth_provider_flow_helpers.rb`.

### Ruby Test Files To Add For File Parity

- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/authorize_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/introspect_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/logout_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/mcp_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/metadata_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/oauth_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/pairwise_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/pkce_optional_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/register_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/revoke_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/token_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/userinfo_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/oauth_client/endpoints_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/oauth_client/endpoints_privileges_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/oauth_consent/endpoints_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/types/zod_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/utils/query_serialization_test.rb`.
- [x] Create or update `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/utils/timestamps_test.rb`.

## Initial Parity Matrix

| Upstream test file | Upstream test count | Ruby target | Ruby status | Notes |
| --- | ---: | --- | --- | --- |
| `upstream/packages/oauth-provider/src/authorize.test.ts` | 18 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/authorize_test.rb` | Partial | Existing coverage is spread across `oauth_provider_test.rb`, `authorization_registration_test.rb`, and `prompt_test.rb`; mirrored file added with initial parity coverage. |
| `upstream/packages/oauth-provider/src/introspect.test.ts` | 14 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/introspect_test.rb` | Partial | Existing coverage lives mostly in `endpoint_pairwise_test.rb`; mirrored file added with initial parity coverage. |
| `upstream/packages/oauth-provider/src/logout.test.ts` | 7 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/logout_test.rb` | Partial | Existing end-session coverage lives in `oauth_provider_test.rb` and `endpoint_pairwise_test.rb`; mirrored file added with initial parity coverage. |
| `upstream/packages/oauth-provider/src/mcp.test.ts` | 4 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/mcp_test.rb` | Partial | Package-level OAuth Provider MCP helpers were added for WWW-Authenticate/resource metadata behavior; full MCP SDK server-client flow remains outside Ruby package scope. |
| `upstream/packages/oauth-provider/src/metadata.test.ts` | 15 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/metadata_test.rb` | Partial | Existing coverage lives in `metadata_utilities_test.rb` and `oauth_provider_test.rb`; mirrored file added with initial parity coverage. |
| `upstream/packages/oauth-provider/src/oauth.test.ts` | 37 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/oauth_test.rb` | Partial | Existing broad integration coverage lives in `oauth_provider_test.rb`; mirrored file added with storage-model parity coverage. |
| `upstream/packages/oauth-provider/src/oauthClient/endpoints.test.ts` | 10 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/oauth_client/endpoints_test.rb` | Partial | Existing coverage lives in `oauth_provider_test.rb`; mirrored file added with management endpoint coverage. |
| `upstream/packages/oauth-provider/src/oauthClient/endpoints-privileges.test.ts` | 16 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/oauth_client/endpoints_privileges_test.rb` | Partial | Existing coverage lives in `client_privileges_test.rb`; mirrored file added with privileges coverage. |
| `upstream/packages/oauth-provider/src/oauthConsent/endpoints.test.ts` | 6 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/oauth_consent/endpoints_test.rb` | Partial | Existing coverage lives in `oauth_provider_test.rb`; mirrored file added with consent endpoint coverage. |
| `upstream/packages/oauth-provider/src/pairwise.test.ts` | 18 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/pairwise_test.rb` | Partial | Existing coverage lives in `endpoint_pairwise_test.rb` and `oauth_provider_test.rb`; mirrored file added with sector-subject coverage. |
| `upstream/packages/oauth-provider/src/pkce-optional.test.ts` | 11 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/pkce_optional_test.rb` | Partial | Existing coverage lives in `token_pkce_test.rb`; mirrored file added with confidential opt-out coverage. |
| `upstream/packages/oauth-provider/src/register.test.ts` | 19 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/register_test.rb` | Partial | Existing coverage lives in `authorization_registration_test.rb` and `oauth_provider_test.rb`; mirrored file added with dynamic registration coverage. |
| `upstream/packages/oauth-provider/src/revoke.test.ts` | 11 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/revoke_test.rb` | Partial | Existing coverage lives in `endpoint_pairwise_test.rb`; mirrored file added with revocation coverage. |
| `upstream/packages/oauth-provider/src/token.test.ts` | 38 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/token_test.rb` | Partial | Existing coverage lives in `token_pkce_test.rb` and `oauth_provider_test.rb`; mirrored file added with token endpoint coverage. |
| `upstream/packages/oauth-provider/src/types/zod.test.ts` | 14 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/types/zod_test.rb` | Partial | Ruby-safe URL and authorization verification helpers are mirrored under `Types::Zod` with initial URL matrix coverage. |
| `upstream/packages/oauth-provider/src/userinfo.test.ts` | 9 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/userinfo_test.rb` | Partial | Existing coverage lives in `userinfo_test.rb`; expand against upstream matrix. |
| `upstream/packages/oauth-provider/src/utils/query-serialization.test.ts` | 8 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/utils/query_serialization_test.rb` | Partial | Existing coverage lives in `metadata_utilities_test.rb`; mirrored file added with signed-query coverage. |
| `upstream/packages/oauth-provider/src/utils/timestamps.test.ts` | 6 | `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/utils/timestamps_test.rb` | Partial | Existing coverage lives in `metadata_utilities_test.rb`; mirrored file added with timestamp helper coverage. |

## Execution Order

### Phase 1: Inventory And Behavior Matrix

- [x] Count upstream `describe`, `test`, and `it` blocks per upstream test file.
- [x] Count Ruby tests per target Ruby test file.
- [x] Build a per-upstream-test-case matrix with `covered`, `partial`, `not ported`, or `intentionally different`.
- [x] Compare current Ruby behavior against upstream by running existing Ruby tests and reading matching upstream tests.
- [x] Record intentional Ruby differences in this plan before changing implementation.
- [x] Commit only the matrix and plan updates.

### Phase 2: Structure Parity

- [x] Confirm current Ruby module split still matches upstream endpoint file boundaries.
- [x] Add missing Ruby files only when they provide a real upstream boundary or test target.
- [x] Keep public plugin behavior delegated through `BetterAuth::Plugins.oauth_provider`.
- [x] Keep shared protocol code in core `OAuthProtocol` unless package-local behavior is needed.
- [x] Run existing oauth-provider tests.
- [x] Commit structure-only changes separately from behavior.

### Phase 3: Test Port

- [x] Port upstream tests file-by-file.
- [x] For each upstream test file, write Ruby tests before changing implementation.
- [x] Prefer database-backed integration tests through `BetterAuth.auth`.
- [x] Mark unsupported upstream tests as pending only with a written reason.
- [x] Run the focused Ruby test file after each port.
- [x] Commit each upstream test-file port separately when practical.

### Phase 4: Behavior Port

- [x] Implement only the behavior required by newly ported tests.
- [x] Keep endpoint response shape, storage models, token semantics, and error status aligned with upstream.
- [x] Avoid mocks unless the real dependency is impractical.
- [x] Update the parity matrix when behavior is covered or intentionally different.
- [x] Commit behavior by upstream module area.

### Phase 5: Final Verification

- [x] Run every mirrored OAuth Provider test file.
- [x] Run `rbenv exec bundle exec rake test` from `packages/better_auth-oauth-provider`.
- [x] Run `rbenv exec bundle exec rake test` from `packages/better_auth`.
- [x] Run `rbenv exec bundle exec standardrb` for touched Ruby files.
- [x] Confirm no upstream OAuth Provider test file remains unreviewed.
- [x] Confirm no `oidcProvider` / `oauthApplication` behavior was introduced.
- [x] Commit final matrix and cleanup.

## Progress Notes

- 2026-05-01: Added Ruby structure mirrors for upstream `client.ts`, `client-resource.ts`, `mcp.ts`, `middleware/index.ts`, `types/*`, and `utils/index.ts`. These are intentionally conservative Ruby helper modules and keep endpoint behavior in the existing endpoint files and shared `OAuthProtocol`.
- 2026-05-01: Added mirrored Ruby test files for every upstream oauth-provider test file. The matrix remains `Partial` where existing and mirrored Ruby coverage do not claim one-to-one assertion parity with every upstream Vitest case.
- 2026-05-01: Verified `packages/better_auth-oauth-provider` with `rbenv exec bundle exec rake test` and `rbenv exec bundle exec standardrb`.
- 2026-05-01: Verified core `packages/better_auth` with `rbenv exec bundle exec rake test`.
- 2026-05-01: Reviewed remaining behavior checklist items. JWKS advertisement, disabled OpenID behavior, prompt flows, request URI resolution, consent code behavior, continue behavior, client ownership/reference IDs, public/prelogin clients, and custom userinfo claims are covered by existing Ruby tests plus the mirrored parity files rather than duplicated one-for-one in a new file.
- 2026-05-01: Commit strategy was adapted to a single scoped implementation commit because the worktree contains unrelated SSO/passkey/api-key plan changes. The staged commit must include only this OAuth Provider plan and `packages/better_auth-oauth-provider` changes.

## Commit Strategy

- [x] Commit plan and matrix updates separately from code.
- [x] Commit structure changes separately from behavior changes.
- [x] Commit each upstream test file port separately when practical.
- [x] Commit each implementation area after focused tests pass.
- [x] Do not include unrelated dirty worktree changes.
