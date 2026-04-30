# OAuth Provider Upstream Test Parity Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use executing-plans or subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Ruby `better_auth-oauth-provider` test suite closer to upstream `@better-auth/oauth-provider` v1.6.9 by translating all applicable missing behavior tests before implementation.

**Architecture:** Add grouped Minitest parity files under `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/` and shared flow helpers under `packages/better_auth-oauth-provider/test/support/`. Production changes should follow RED/GREEN, with each failing translated test driving the minimum Ruby implementation.

**Tech Stack:** Ruby, Minitest, Rack mock requests, in-memory BetterAuth adapter, upstream Better Auth v1.6.9 as reference.

**Traceability:** See `.docs/plans/2026-04-29-oauth-provider-upstream-test-parity-matrix.md` for the upstream file-by-file coverage matrix and explicit exclusions.

---

### Task 1: Baseline and Shared Test Helpers

**Files:**
- Create: `packages/better_auth-oauth-provider/test/support/oauth_provider_flow_helpers.rb`
- Modify: `packages/better_auth-oauth-provider/test/test_helper.rb`

- [x] Run the existing OAuth provider suite with `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb`.
- [x] Add helper methods for `build_auth`, sign-up cookies, PKCE values, client creation, authorization-code exchange, refresh/introspection bodies, and Rack env generation.
- [x] Keep helpers public to Minitest classes via `include OAuthProviderFlowHelpers`.

### Task 2: Translate Missing Upstream Tests

**Files:**
- Create grouped tests in `packages/better_auth-oauth-provider/test/better_auth/oauth_provider/`

- [x] Authorization: login redirects, `prompt=none`, PAR `request_uri`, `iss` propagation, issuer normalization gaps.
- [x] Metadata/init: full metadata fields, invalid advertised scopes, custom claims, `disable_jwt_plugin`, secondary-storage constraints.
- [x] Registration/SafeUrl: DCR errors, confidential/public type matrix, metadata filtering, SafeUrl accept/reject matrix.
- [x] Client/consent endpoints: privilege checks, immutable fields, public access, consent scope validation.
- [x] Prompt flows: login/create/select_account/post_login/consent combinations and JSON continuation. Progress: prompt login/create/select/post-login parity added; JS/browser-only fetch redirect ergonomics excluded.
- [x] Token flows: authorization-code, refresh, client credentials, custom claims, loopback redirects, scope expirations. Progress: upstream server-side token matrix covered; TS schema-only tests excluded.
- [x] PKCE optional: confidential opt-out, public/offline enforcement, mismatch failures, admin persistence.
- [x] Introspection/revocation/userinfo/logout/pairwise: add upstream behavior coverage not already represented by the legacy broad file.
- [x] Utilities/rate limits: query serialization, timestamp/auth_time behavior, route rate-limit enforcement.

### Task 3: Confirm RED

- [x] Run each new grouped file and confirm failures are real behavior gaps, not syntax/helper errors.
- [x] Keep production files unchanged until this step is complete.

### Task 4: Implement Missing Behavior

**Files likely touched:**
- `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`
- `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`

- [x] Implement only behavior required by the translated tests.
- [x] Preserve Ruby option names while keeping upstream HTTP paths and JSON keys.
- [x] Prefer existing adapter/context APIs and avoid new dependencies.

### Task 5: Verify

- [x] Run all new parity tests.
- [x] Run `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb`.
- [x] Run package-level `cd packages/better_auth-oauth-provider && rbenv exec bundle exec rake test`.

### Current Remaining Work

- [x] Complete exact upstream token matrix for auth-code, refresh, and client-credentials response variants.
- [x] Complete no-hint/logged-out introspection matrix.
- [x] Complete no-hint revocation matrix.
- [x] Complete remaining pairwise same-sector/refresh/JWT-resource cases.
- [x] Add token endpoint rate-limit enforcement tests once the Ruby rate limiter behavior is mapped against upstream.

### Explicit Exclusions

- [x] Exclude MCP/resource-client tests until Ruby adds those package features.
- [x] Exclude JS client/browser/fetch redirect ergonomics.
- [x] Cover organization/team OAuth provider integration through Ruby organization plugin APIs.
- [x] Exclude TypeScript/Zod schema-unit tests when covered through public Ruby behavior.
