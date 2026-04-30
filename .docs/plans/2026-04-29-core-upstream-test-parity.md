# Core Upstream Test Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Translate every Ruby-applicable Better Auth v1.6.9 core/server upstream test into `packages/better_auth` Minitest coverage before completing parity implementations.

**Architecture:** Keep `better_auth` as the Ruby core package and add missing upstream-equivalent helpers under `BetterAuth::`. Browser clients, TypeScript type inference, Next.js integration, and separately packaged Ruby gems stay outside this core parity plan.

**Tech Stack:** Ruby 3.2+, Minitest, Rack, existing in-gem dependencies only.

---

## Scope

- [x] Confirm upstream submodule content exists at Better Auth `v1.6.9`.
- [x] Core scope is `packages/better_auth`, including base auth, routes, providers, and built-in plugins mirrored from `upstream/packages/better-auth/src/plugins`.
- [x] Exclude browser/client suites, Next.js integration, TypeScript type inference, MCP browser client, and organization client inference.
- [ ] Translate all server-applicable upstream test titles into Ruby Minitest tests or document a Ruby-specific exclusion. OAuth/social is complete in child plan `2026-04-30-core-oauth-social-upstream-parity.md`.
- [x] Implement first missing-suite block after translated tests exist.
- [x] Run `cd packages/better_auth && bundle exec rake test`.
- [x] Run `cd packages/better_auth && bundle exec standardrb`.

## Audit Table

| Upstream file | Upstream test title | Ruby target file | Status | Ruby adaptation note |
| --- | --- | --- | --- | --- |
| `upstream/packages/better-auth/src/utils/url.test.ts` | proxy header validation, host/protocol extraction, dynamic base URL resolution, host pattern matching | `packages/better_auth/test/better_auth/url_helpers_test.rb` | Ported-first-pass | Server-side URL helpers only; browser `window` fallback is out of scope. |
| `upstream/packages/core/src/utils/host.test.ts` | host canonicalization, RFC 6890 classification, loopback/public predicates, SSRF bypass cases | `packages/better_auth/test/better_auth/host_test.rb` | Ported-first-pass | Ruby uses `IPAddr` plus explicit tunnel and metadata handling. |
| `upstream/packages/core/src/oauth2/validate-token.test.ts` | RS256/ES256/EdDSA JWT validation, `kid`, audience, issuer, JWKS errors | `packages/better_auth/test/better_auth/oauth2_test.rb` | Ported-first-pass | RS256/ES256 and JWKS error coverage is implemented; EdDSA should be covered in a follow-up if the current JWT dependency exposes suitable public key import. |
| `upstream/packages/core/src/oauth2/refresh-access-token.test.ts` | access and refresh token expiration mapping | `packages/better_auth/test/better_auth/oauth2_test.rb` | Ported-first-pass | HTTP is injected with a fetcher callable for testability. |
| `upstream/packages/core/src/utils/async.test.ts` | bounded concurrent map ordering, concurrency clamping, failure behavior | `packages/better_auth/test/better_auth/async_test.rb` | Ported-first-pass | AbortSignal-specific behavior is not a direct Ruby runtime concept. |
| `upstream/packages/core/src/context/request-state.test.ts` | request-local state lifecycle and isolation | `packages/better_auth/test/better_auth/request_state_test.rb` | Ported-first-pass | Ruby uses thread-local request state. |
| `upstream/packages/core/src/utils/deprecate.test.ts` | warn once wrapper and return value preservation | `packages/better_auth/test/better_auth/deprecate_test.rb` | Ported-first-pass | Ruby wrapper preserves block return and logger injection. |
| `upstream/packages/core/src/env/logger.test.ts` | log-level publishing matrix | `packages/better_auth/test/better_auth/logger_test.rb` | Ported-first-pass | Color formatting is not part of Ruby public behavior. |
| `upstream/packages/core/src/instrumentation/*.test.ts` | no-op tracing surface and span behavior | `packages/better_auth/test/better_auth/instrumentation_test.rb` | Ported-first-pass | Ruby starts with a no-op instrumentation surface unless OpenTelemetry is later approved. |
| `upstream/packages/better-auth/src/instrumentation.endpoint.test.ts` | endpoint spans and route attributes | `packages/better_auth/test/better_auth/instrumentation_test.rb` | TODO | Needs endpoint/router instrumentation after no-op core surface exists. |
| `upstream/packages/better-auth/src/instrumentation.db.test.ts` | adapter operation spans and plugin hook attributes | `packages/better_auth/test/better_auth/instrumentation_test.rb` | TODO | Needs internal adapter instrumentation after no-op core surface exists. |
| `upstream/packages/better-auth/src/api/to-auth-endpoints.test.ts` | endpoint conversion, hook mutation, direct API responses, disabled paths, proxy/base URL/security helpers | `packages/better_auth/test/better_auth/api_test.rb`, `packages/better_auth/test/better_auth/endpoint_test.rb`, `packages/better_auth/test/better_auth/router_test.rb` | Ported | JavaScript debug stack trace and cross-realm Request object cases are runtime-specific exclusions. |
| `upstream/packages/better-auth/src/api/index.test.ts` | context preparation, plugin request chain, trailing slash behavior | `packages/better_auth/test/better_auth/api_test.rb`, `packages/better_auth/test/better_auth/router_test.rb` | Ported | Promise-based context resolution is adapted to Ruby's synchronous context preparation. |
| `upstream/packages/better-auth/src/api/check-endpoint-conflicts.test.ts` | endpoint conflict matrix and logger shape | `packages/better_auth/test/better_auth/router_test.rb` | Ported | Method-array and wildcard conflicts are covered with Ruby endpoint method arrays. |
| `upstream/packages/better-auth/src/api/middlewares/origin-check.test.ts` | origin, CSRF, callback URL, Fetch Metadata, and skip-origin behavior | `packages/better_auth/test/better_auth/router_test.rb` | Ported | Path-scoped skip behavior is represented through Ruby `advanced.disable_origin_check` arrays. |
| `upstream/packages/better-auth/src/api/rate-limiter/rate-limiter.test.ts` | rate-limit rules, storage, retry headers, missing-IP fallback, and IP normalization | `packages/better_auth/test/better_auth/router_test.rb`, `packages/better_auth/test/better_auth/request_ip_test.rb` | Ported | Ruby uses Rack request IP extraction and existing memory/secondary storage test helpers. |
| `upstream/packages/better-auth/src/api/routes/{account,password,session-api,sign-up,sign-in,email-verification,update-user,sign-out,error}.test.ts` | Base auth route behavior: sessions, sign-up/sign-in, accounts/social account utilities, password reset, email verification, user update/delete, sign-out, and error pages | `packages/better_auth/test/better_auth/routes/*_test.rb` | Ported | Child plan `2026-04-30-core-base-routes-upstream-parity.md` now marks every upstream base-route title as ported, covered by existing Ruby tests, or a Ruby-specific exclusion. |
| `upstream/packages/better-auth/src/plugins/test-utils/test-utils.test.ts` | upstream TypeScript test helper plugin | `packages/better_auth/test/test_helper.rb` | Review | Translate only reusable Ruby test helpers; do not expose as production plugin unless needed. |
| `upstream/packages/better-auth/src/client/**/*.test.ts` | browser/client package behavior | N/A | Out of scope | Ruby core is server-side Rack library. |
| `upstream/packages/better-auth/src/integrations/next-js.test.ts` | Next.js integration behavior | N/A | Out of scope | Covered by Ruby framework adapter packages, not core. |
| `upstream/packages/better-auth/src/types/types.test.ts` | TypeScript type inference | N/A | Out of scope | No Ruby runtime behavior. |
| `upstream/packages/better-auth/src/plugins/mcp/client/mcp-client.test.ts` | MCP client package behavior | N/A | Out of scope | Ruby core covers MCP server endpoints only. |
| `upstream/packages/better-auth/src/plugins/organization/client.test.ts` | organization client inference | N/A | Out of scope | Ruby core covers organization server behavior only. |
| `upstream/packages/better-auth/src/oauth2/utils.test.ts` | OAuth token decrypt/encrypt migration utilities | `packages/better_auth/test/better_auth/routes/account_test.rb` | Ported | Ruby uses the core AES-GCM base64url encrypted payload shape instead of upstream's hex-looking payload. |
| `upstream/packages/better-auth/src/oauth2/link-account.test.ts` | account linking email verification, trusted/untrusted providers, `disableImplicitLinking`, profile override, provider-scoped lookup, providers without email | `packages/better_auth/test/better_auth/routes/social_test.rb` | Ported | Ruby uses injected provider callbacks and memory adapter instead of MSW network mocks. |
| `upstream/packages/better-auth/src/social.test.ts` | social sign-in/callback matrix, provider factories, profile mapping, PKCE/scopes, multi-client IDs, provider-specific Apple/Vercel/Microsoft/Railway cases | `packages/better_auth/test/better_auth/routes/social_test.rb`, `packages/better_auth/test/better_auth/routes/account_test.rb`, `packages/better_auth/test/better_auth/social_providers_test.rb` | Ported | Promise-style async provider factory is documented as a Ruby exclusion; provider behavior is synchronous callable/hash configuration. |
| `upstream/packages/better-auth/src/plugins/{organization,admin,email-otp,two-factor,generic-oauth,jwt,username,device-authorization,phone-number,mcp,oauth-proxy,multi-session,additional-fields,custom-session}` | Built-in server plugin behavior | `packages/better_auth/test/better_auth/plugins/*_test.rb` | Covered by existing Ruby test | Coordinator plan `2026-04-30-core-plugins-upstream-parity.md` now maps every listed title group to focused Ruby tests, child plans, or Ruby exclusions. |
| `upstream/packages/better-auth/src/db/{db,internal-adapter,get-migration-schema,secondary-storage,to-zod}.test.ts` | DB/schema/internal adapter behavior | `packages/better_auth/test/better_auth/{adapters,schema,routes}/*_test.rb` | Ported | Child plan `2026-04-30-core-db-schema-upstream-parity.md` maps every DB/schema title to ported coverage, existing Ruby coverage, or documented Ruby exclusion. |

## Partial Suite Follow-Up

- [x] Audit `context/create-context.test.ts`, `auth/full.test.ts`, `auth/minimal.test.ts`, `auth/trusted-origins.test.ts`, and `call.test.ts` against `auth_test.rb` and `configuration_test.rb`. Child plan: `2026-04-30-core-auth-context-upstream-parity.md`.
- [x] Audit `api/to-auth-endpoints.test.ts`, `api/index.test.ts`, `api/check-endpoint-conflicts.test.ts`, `origin-check.test.ts`, and `rate-limiter.test.ts` against `api_test.rb`, `endpoint_test.rb`, and `router_test.rb`. Child plan: `2026-04-30-core-api-router-upstream-parity.md`.
- [x] Audit base route suites for account, password, session, sign-up, sign-in, email verification, update-user, sign-out, and error routes. Child plan: `2026-04-30-core-base-routes-upstream-parity.md`.
- [x] Audit DB/schema suites for internal adapter, migration schema, secondary storage, and schema input/output filtering. Child plan: `2026-04-30-core-db-schema-upstream-parity.md`.
- [x] Audit OAuth/social suites for account linking, token encryption/decryption, refresh token, provider profile, and social sign-in behavior. Child plan: `2026-04-30-core-oauth-social-upstream-parity.md`.
- [x] Audit high-gap plugin suites: organization, admin, email-otp, two-factor, generic-oauth, jwt, username, device-authorization, phone-number, mcp, oauth-proxy, multi-session, additional-fields, and custom-session. Child plan: `2026-04-30-core-plugins-upstream-parity.md`.

## Package Boundary Decision

- [x] Keep `packages/better_auth` as the Ruby core gem for social providers, OAuth2 helpers, DB schema, rate limiting, cookies, and security utilities.
- [x] Keep separate gems only where upstream has separate distributable packages or heavyweight dependencies: passkey, sso, scim, oauth-provider, stripe, and adapters.
