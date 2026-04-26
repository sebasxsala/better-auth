# Phase 11 Protocol Plugins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` when possible, or `executing-plans` to implement this plan task-by-task. Steps use checkbox syntax for progress tracking.

**Goal:** Port Better Auth protocol-heavy Phase 11 plugins into the Ruby core gem: OIDC provider, OAuth provider, device authorization, and MCP.

**Architecture:** Implement protocol plugins in `packages/better_auth` only, sharing OAuth/OIDC helpers for issuer validation, PKCE, client authentication, token storage, metadata, userinfo, revocation, and introspection. Preserve upstream HTTP routes and wire contracts where practical, while documenting Ruby-specific storage and packaging adaptations.

**Tech Stack:** Ruby 3.2+, Rack 3, Minitest, JSON, JWT, BCrypt, existing BetterAuth plugin/endpoint/adapter APIs, and upstream TypeScript source under `upstream/`.

---

## Upstream References

- OIDC provider source: `upstream/packages/better-auth/src/plugins/oidc-provider/`
- OIDC provider tests: `upstream/packages/better-auth/src/plugins/oidc-provider/oidc.test.ts`, `upstream/packages/better-auth/src/plugins/oidc-provider/utils/prompt.test.ts`
- OAuth provider source: `upstream/packages/oauth-provider/src/`
- OAuth provider tests: `upstream/packages/oauth-provider/src/*.test.ts`, `upstream/packages/oauth-provider/src/oauthClient/endpoints.test.ts`, `upstream/packages/oauth-provider/src/oauthConsent/endpoints.test.ts`
- Device authorization source/tests: `upstream/packages/better-auth/src/plugins/device-authorization/`, `device-authorization.test.ts`
- MCP source/tests: `upstream/packages/better-auth/src/plugins/mcp/`, `mcp.test.ts`, plus `upstream/packages/oauth-provider/src/mcp.ts`

## Implementation Checklist

- [x] Port OIDC prompt parsing and OAuth issuer URL validation tests first.
- [x] Create shared OAuth/OIDC helper modules without adding runtime dependencies.
- [x] Implement `BetterAuth::Plugins.oidc_provider` with metadata, registration, authorize/consent, token, userinfo, refresh, and logout routes.
- [x] Implement `BetterAuth::Plugins.oauth_provider` package behavior under Ruby plugin namespaces.
- [x] Implement `BetterAuth::Plugins.device_authorization` with RFC device-code polling, approval, denial, expiry, and slow-down behavior.
- [x] Implement `BetterAuth::Plugins.mcp` as a thin layer over OIDC/OAuth helpers with protected-resource metadata and MCP-prefixed OAuth routes.
- [x] Add feature docs for each plugin.
- [x] Update parity matrix and this master plan only after tests pass.

## Verification

- [x] `cd packages/better_auth && rbenv exec bundle exec rake test TEST=test/better_auth/plugins/oidc_provider_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec rake test TEST=test/better_auth/plugins/oauth_provider_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec rake test TEST=test/better_auth/plugins/device_authorization_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec rake test TEST=test/better_auth/plugins/mcp_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec rake test TEST=test/better_auth/plugins/jwt_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec rake test TEST=test/better_auth/plugins/generic_oauth_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec rake test TEST=test/better_auth/routes/session_routes_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec rake test TEST=test/better_auth/session_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec rake test TEST=test/better_auth/router_test.rb`
- [ ] `cd packages/better_auth && rbenv exec bundle exec rake test`
- [x] `cd packages/better_auth && RUBOCOP_CACHE_ROOT=/var/folders/7x/jrsz946d2w73n42fb1_ff5000000gn/T/rubocop_cache rbenv exec bundle exec standardrb <phase-11-files>`

## Assumptions

- Phase 11 stays framework-agnostic in `packages/better_auth`; Rails integration is out of scope.
- Existing worktree changes are user-owned and must not be reverted.
- Upstream behavior wins for public route paths, JSON keys, OAuth parameter names, and error strings.
- Ruby can store array/json values natively in the memory adapter; SQL encoding differences must be documented.
- Organization-specific OAuth provider behavior is deferred unless Phase 10 is present in the implementation branch.
