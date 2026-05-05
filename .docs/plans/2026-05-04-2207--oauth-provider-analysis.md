# OAuth Provider Analysis And Hardening Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` or `subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `better_auth-oauth-provider` against the remaining high-value upstream parity and security gaps found during analysis.

**Architecture:** The OAuth provider gem owns route behavior, docs, metadata, and tests. Shared OAuth token/client mechanics live in `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`, with JWT signing support reused from the core JWT plugin helpers where possible.

**Tech Stack:** Ruby 3.2+, Minitest, Rack, `better_auth`, `better_auth-oauth-provider`, upstream Better Auth OAuth provider v1.6.9 as behavioral reference.

---

## Implementation Steps

- [x] Add opaque-token client ownership checks in introspection and revocation so client B cannot introspect or revoke client A's access/refresh tokens. Also strip a leading `Bearer ` token prefix in introspection to match upstream.
- [x] Wire `/oauth2/public-client-prelogin` to enforce `allow_public_client_prelogin` and a valid signed `oauth_query`; add tests for disabled, missing/invalid signature, and valid access.
- [x] Harden `/oauth2/update-client` and `/admin/oauth2/update-client` by validating merged client metadata: safe redirect/logout URLs, grant/response/auth-method enums, public-client constraints, pairwise subject rules, and scope allow-lists.
- [x] Align token signing with metadata: use the JWT plugin signer/verifier for JWT access tokens and ID tokens when enabled; use `id_token_expires_in`; keep HS256 fallback and logout verification working when JWT is disabled.
- [x] Harden `resource` handling: default valid audiences to the auth base URL, include `/oauth2/userinfo` when `openid` is granted, reject arbitrary audiences unless explicitly configured, and preserve configured `valid_audiences`.
- [x] Align `client_credentials`: reject explicitly requested OIDC user scopes (`openid`, `profile`, `email`, `offline_access`) and add `client_credential_grant_default_scopes` for clients without stored scopes.
- [x] Update docs and README route tables to the current canonical endpoints (`/oauth2/get-client`, `/oauth2/get-clients`, consent CRUD paths, POST prelogin) and note legacy aliases separately.
- [x] Add a short plan note that upstream `oauthProviderResourceClient` and MCP resource-server helpers remain separate future work, not part of this package hardening pass.

## Test Plan

- [x] Add regression tests for cross-client introspection/revocation denial.
- [x] Add regression tests for prelogin gating and signed `oauth_query`.
- [x] Add update-client tests proving unsafe redirect URI and invalid grant/auth combinations are rejected.
- [x] Add JWT plugin tests proving token header `alg` matches metadata and introspection verifies the produced JWT.
- [x] Run targeted OAuth provider tests for introspection, revocation, token, client endpoints, metadata, logout, and docs examples where applicable.
- [x] Run `rbenv exec bundle exec rake test` in `packages/better_auth-oauth-provider`.
- [x] Run `rbenv exec bundle exec standardrb` in `packages/better_auth-oauth-provider`.

## Execution Notes

- Ruby-specific adaptation: JWT access tokens and ID tokens use the Ruby JWT plugin when it is registered; when the plugin is absent, the OAuth provider keeps the existing HS256 fallback for compatibility.
- Resource JWT audiences now include the UserInfo endpoint whenever `openid` is granted and a resource token is requested.
- Relevant core checks also passed after touching `OAuthProtocol`: OIDC provider tests, MCP authorization/token/userinfo tests, `standardrb`, and the full `packages/better_auth` test suite.

## Assumptions

- Use the local workspace timestamp from `date +%Y-%m-%d-%H%M`, which returned `2026-05-04-2207`.
- Do not bump gem versions; this is unreleased hardening work.
- Do not recreate deleted `.docs/future/*` files unless implementation discovers the future-work note needs a separate document.
