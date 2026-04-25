# Better Auth Ruby Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` when the work can be split into independent tasks, or `executing-plans` when implementing sequentially in one session. Steps use checkbox syntax for progress tracking. Mark checkboxes as each step is completed and keep this plan current.

**Goal:** Port upstream Better Auth v1.4.22 from TypeScript into an idiomatic Ruby/Rack core gem and Rails adapter while preserving upstream product behavior, route paths, wire contracts, plugin features, and test coverage wherever Ruby makes that possible.

**Architecture:** The Ruby port must mirror upstream's product architecture: auth factory -> context -> Rack handler/router -> endpoints and plugins -> cookies/sessions -> internal adapter -> database or secondary storage. Internals should be idiomatic Ruby, but public HTTP behavior, option concepts, plugin contracts, schemas, cookie names, route paths, error codes, and tests should follow upstream as the source of truth.

**Tech Stack:** Ruby 3.2+, Rack 3, Minitest, RSpec for Rails, StandardRB, JSON, JWT, BCrypt, Rails/ActiveRecord in `better_auth-rails`, and `upstream/` as the reference implementation.

---

## Operating Rules

- [ ] Before implementing any feature, read the matching upstream source and tests under `/Users/sebastiansala/projects/better-auth/upstream`.
- [ ] Copy or adapt upstream tests first, then write Ruby code until those tests pass.
- [ ] Keep `packages/better_auth` framework-agnostic. No Rails constants, ActiveRecord assumptions, controller helpers, or Rails middleware belong in the core gem.
- [ ] Keep Rails integration in `packages/better_auth-rails`.
- [ ] Preserve upstream route paths, JSON keys, cookie names, error code strings, redirect query params, OAuth parameter names, and documented option names unless this plan explicitly states a Ruby adaptation.
- [ ] Use idiomatic Ruby naming for internal methods and files, but document the mapping when the public concept comes from upstream camelCase.
- [ ] After each completed task, update this file's checkbox and add or update the related `.docs/features/*.md` entry.
- [ ] Do not mark a feature complete unless its Ruby tests pass and its upstream parity notes are documented.

## Upstream Architecture Map

The upstream TypeScript runtime works like this:

```txt
betterAuth(options)
  -> createAuthContext(adapter, options)
  -> auth.handler(request) and auth.api.*
  -> router(basePath=/api/auth)
  -> base endpoints + plugin endpoints
  -> origin checks + middleware + hooks + rate limit
  -> cookies/session/token handling
  -> internalAdapter
  -> database adapter or secondaryStorage
```

The Ruby target must keep the same conceptual layers:

```txt
BetterAuth.auth(options)
  -> BetterAuth::Context
  -> BetterAuth::RackApp#call(env)
  -> BetterAuth::Router
  -> BetterAuth::Endpoint + BetterAuth::API
  -> BetterAuth::Cookies / BetterAuth::SessionStore
  -> BetterAuth::Adapters::InternalAdapter
  -> BetterAuth::Adapters::{Memory, SQL, Rails}
  -> BetterAuth::Plugins::*
```

Primary upstream references:

- `/Users/sebastiansala/projects/better-auth/upstream/packages/better-auth/src/auth/base.ts`
- `/Users/sebastiansala/projects/better-auth/upstream/packages/better-auth/src/context/create-context.ts`
- `/Users/sebastiansala/projects/better-auth/upstream/packages/better-auth/src/api/index.ts`
- `/Users/sebastiansala/projects/better-auth/upstream/packages/better-auth/src/api/to-auth-endpoints.ts`
- `/Users/sebastiansala/projects/better-auth/upstream/packages/better-auth/src/cookies/index.ts`
- `/Users/sebastiansala/projects/better-auth/upstream/packages/better-auth/src/db/internal-adapter.ts`
- `/Users/sebastiansala/projects/better-auth/upstream/packages/core/src/types/plugin.ts`

## Phase 0: Inventory, Test Matrix, And Documentation Harness

**Purpose:** Create a living map of everything to port before implementation starts.

**Files:**

- Create: `/Users/sebastiansala/projects/better-auth/.docs/features/upstream-parity-matrix.md`
- Modify: `/Users/sebastiansala/projects/better-auth/.docs/README.md`
- Keep current: `/Users/sebastiansala/projects/better-auth/.docs/plans/2026-04-25-better-auth-ruby-port.md`

Steps:

- [x] Create an upstream parity matrix with columns: upstream package, upstream source path, upstream test path, Ruby target path, Ruby test path, route paths, schema tables, status, notes.
- [x] Add every core subsystem to the matrix: `auth`, `context`, `api`, `cookies`, `crypto`, `db`, `adapters`, `oauth2`, `social-providers`, `utils`, `client`, `integrations`.
- [x] Add every base route to the matrix: `/ok`, `/error`, `/sign-up/email`, `/sign-in/email`, `/sign-in/social`, `/callback/:providerId`, `/sign-out`, `/get-session`, `/list-sessions`, `/revoke-session`, `/revoke-sessions`, `/revoke-other-sessions`, `/request-password-reset`, `/reset-password`, `/verify-password`, `/send-verification-email`, `/verify-email`, `/update-user`, `/change-email`, `/change-password`, `/set-password`, `/delete-user`, `/delete-user/callback`, `/list-accounts`, `/link-social`, `/unlink-account`, `/get-access-token`, `/refresh-token`, `/account-info`.
- [x] Add every plugin to the matrix: `access`, `additional-fields`, `admin`, `anonymous`, `api-key`, `bearer`, `captcha`, `custom-session`, `device-authorization`, `email-otp`, `generic-oauth`, `haveibeenpwned`, `jwt`, `last-login-method`, `magic-link`, `mcp`, `multi-session`, `oauth-proxy`, `oidc-provider`, `one-tap`, `one-time-token`, `open-api`, `organization`, `phone-number`, `siwe`, `two-factor`, `username`, `passkey`, `sso`, `scim`, `oauth-provider`, `stripe`, `expo`.
- [x] Add docs/demo references to the matrix: upstream `docs/content/docs`, `demo/nextjs`, `demo/stateless`, `demo/expo`, `demo/oidc-client`.
- [x] Update `.docs/README.md` to explain that `.docs/plans` stores implementation plans and `.docs/features` stores feature parity notes.
- [x] Verify the generated docs by checking that every upstream area has a row. Product tests were also run because this session's user instruction requires tests on every task.

## Phase 1: Core Gem Skeleton And Public API

**Purpose:** Establish the Ruby entrypoint and object model before porting behavior.

**Files:**

- Modify: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth.rb`
- Modify: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/core.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/auth.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/configuration.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/context.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/error.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/auth_test.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/configuration_test.rb`

Steps:

- [ ] Port upstream auth initialization tests from `upstream/packages/better-auth/src/auth/full.test.ts`, `minimal.test.ts`, and `trusted-origins.test.ts`.
- [x] Define `BetterAuth.auth(options = {})` returning an object with `handler`, `api`, `options`, `context`, and `error_codes`.
- [x] Define `BetterAuth::Auth#call(env)` as a Rack-compatible alias to the handler.
- [x] Define `BetterAuth::Configuration` with upstream option concepts: `base_url`, `base_path`, `secret`, `database`, `plugins`, `trusted_origins`, `rate_limit`, `session`, `account`, `advanced`, `email_and_password`, `social_providers`, `secondary_storage`, `database_hooks`, `hooks`.
- [x] Preserve upstream defaults: `base_path` is `/api/auth`, session expiry is 7 days, update age is 24 hours, fresh age is 24 hours, password length is 8 to 128, and DB-less mode enables stateless session defaults.
- [x] Validate secret like upstream: missing secret fails outside tests, default secret is allowed only in test, short or low-entropy secret warns.
- [x] Implement `BetterAuth::Context` with mutable runtime fields matching upstream: app name, base URL, version, options, social providers, cookies, adapter, internal adapter, logger, session config, rate limit config, trusted origins, secret, current session, new session.
- [x] Add tests for default config, explicit config, secret validation, base URL inference, trusted origins, and plugin list normalization.
- [x] Run `cd packages/better_auth && bundle exec rake test TEST=test/better_auth/auth_test.rb`.
- [x] Run `cd packages/better_auth && bundle exec rake test TEST=test/better_auth/configuration_test.rb`.
- [x] New Phase 1 tests pass and StandardRB passes for touched files.

## Phase 2: Endpoint, API, Router, Middleware, Hooks

**Purpose:** Build the request execution pipeline that all routes and plugins will share.

**Files:**

- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/endpoint.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/router.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/api.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/middleware/origin_check.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/rate_limiter.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/endpoint_test.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/router_test.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/api_test.rb`

Steps:

- [x] Port upstream tests from `api/index.test.ts`, `api/to-auth-endpoints.test.ts`, `api/middlewares/origin-check.test.ts`, and `api/check-endpoint-conflicts.test.ts`. Ruby Phase 2 uses synthetic endpoints for pipeline parity because full auth/session route behavior is deferred to later phases.
- [x] Implement `BetterAuth::Endpoint` with `path`, `method`, `body_schema`, `query_schema`, `headers_schema`, `metadata`, and callable handler.
- [x] Implement endpoint result handling for JSON bodies, redirects, raw Rack responses, headers, status, cookies, and raised API errors.
- [x] Implement before and after endpoint hooks with upstream ordering: before hooks may modify context or short-circuit; after hooks may replace response.
- [x] Implement `BetterAuth::API` so server-side calls can invoke endpoints directly and return data or Rack response depending on call options.
- [x] Implement `BetterAuth::Router` under `base_path` with disabled paths, method checks, route params, trailing slash behavior, plugin endpoint merge, and endpoint conflict logging.
- [x] Implement router middleware ordering: origin check, plugin middlewares, plugin `on_request`, rate limit, endpoint, plugin `on_response`.
- [x] Document in the feature notes that direct `auth.api` calls intentionally do not pass through all Rack router middleware, matching upstream behavior.
- [x] Add tests for conflict detection by endpoint key, path, and method.
- [x] Add tests for Rack `GET` and `POST` requests under `/api/auth`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec rake test TEST=test/better_auth/endpoint_test.rb`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec rake test TEST=test/better_auth/router_test.rb`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec rake test TEST=test/better_auth/api_test.rb`.
- [x] Document the Phase 2 dependency decision: do not add `rack-attack`, `rack-protection`, `dry-validation`, `addressable`, or `public_suffix` as required core runtime dependencies yet; keep Better Auth-specific origin/rate/schema behavior in core and expose custom storage/schema adapters for future integration.

## Phase 3: Database Schema, Adapters, And Internal Adapter

**Purpose:** Create the persistence contract that all auth flows and plugins use.

**Files:**

- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/schema.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/adapters/base.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/adapters/memory.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/adapters/internal_adapter.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/database_hooks.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/schema_test.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/adapters/memory_test.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/adapters/internal_adapter_test.rb`

Steps:

- [ ] Port upstream tests from `db/*.test.ts`, `db/internal-adapter.test.ts`, `db/secondary-storage.test.ts`, and adapter factory tests.
- [ ] Define core schema tables: `user`, `session`, `account`, `verification`, `rateLimit`.
- [ ] Preserve upstream field names for storage and wire behavior: `id`, `name`, `email`, `emailVerified`, `image`, `createdAt`, `updatedAt`, `userId`, `token`, `expiresAt`, `ipAddress`, `userAgent`, `providerId`, `accountId`, `accessToken`, `refreshToken`, `idToken`, `scope`, `password`, `identifier`, `value`.
- [ ] Implement schema merge for plugin schemas and additional fields.
- [ ] Implement adapter operations: `create`, `find_one`, `find_many`, `update`, `update_many`, `delete`, `delete_many`, `count`, and `transaction`.
- [ ] Implement memory adapter first; it is the default when no database is provided.
- [ ] Implement `InternalAdapter` methods matching upstream semantics: user creation, OAuth user creation, account linking, session creation, session lookup, session update, session deletion, account lookup, verification value lifecycle, user listing, user count, password update.
- [ ] Implement database hooks for create, update, update many, delete, and delete many.
- [ ] Implement `secondary_storage` session behavior with token TTL and `active-sessions-*` lists.
- [ ] Run schema, memory adapter, and internal adapter tests.
- [ ] Add `.docs/features/database-adapters.md` with upstream links and Ruby storage decisions.

## Phase 4: Crypto, Cookies, Passwords, Sessions

**Purpose:** Match upstream's security-sensitive behavior before implementing full auth routes.

**Files:**

- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/crypto.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/password.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/cookies.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/session_store.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/session.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/crypto_test.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/cookies_test.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/session_test.rb`

Steps:

- [ ] Port upstream `cookies/cookies.test.ts`, `client/session-refresh.test.ts`, and session route tests that only depend on session primitives.
- [ ] Implement secure random ID generation and UUID mode.
- [ ] Implement HMAC signing, signature verification, constant-time comparison, hashing helpers, symmetric encryption helpers, and JWT helpers needed by later plugins.
- [ ] Implement BCrypt password hash and verify with configurable callbacks.
- [ ] Implement cookie naming, prefixing, default attributes, secure cookie options, cross-subdomain attributes, and advanced cookie overrides.
- [ ] Implement signed `session_token` cookies.
- [ ] Implement `session_data` cookie cache, max age, refresh cache behavior, and disabling cache per request.
- [ ] Implement cookie chunking and deletion for oversized cookie values.
- [ ] Implement session lookup priority: signed cookie parse, cookie cache when allowed, adapter or secondary storage lookup, expiration refresh, response cookie update.
- [ ] Add sensitive session behavior that bypasses stale cookie cache for sensitive routes.
- [ ] Run crypto, cookie, and session tests.
- [ ] Add `.docs/features/sessions-and-cookies.md`.

## Phase 5: Base Auth Routes

**Purpose:** Ship the core Better Auth product without optional plugins.

**Files:**

- Create route files under `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/routes/`
- Create matching tests under `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/routes/`
- Modify: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/core.rb`

Steps:

- [ ] Port upstream base route tests from `api/routes/*.test.ts`.
- [ ] Implement `/ok` and `/error`.
- [ ] Implement `/sign-up/email` with email normalization, password validation, user creation, account creation, optional email verification, auto sign-in, callback URL behavior, and sign-up disabled behavior.
- [ ] Implement `/sign-in/email` with password validation, banned/sensitive checks once plugins exist, session creation, remember-me behavior, and cookie setting.
- [ ] Implement `/sign-in/social` and `/callback/:providerId` with OAuth state strategy, provider lookup, callback URL validation, new user callback, error callback, account linking, and token storage.
- [ ] Implement `/sign-out`.
- [ ] Implement `/get-session`, `/list-sessions`, `/revoke-session`, `/revoke-sessions`, `/revoke-other-sessions`.
- [ ] Implement `/request-password-reset`, `/request-password-reset/callback`, `/reset-password`, `/verify-password`.
- [ ] Implement `/send-verification-email` and `/verify-email`.
- [ ] Implement `/update-user`, `/change-email`, `/change-password`, `/set-password`, `/delete-user`, `/delete-user/callback`.
- [ ] Implement `/list-accounts`, `/link-social`, `/unlink-account`, `/get-access-token`, `/refresh-token`, `/account-info`.
- [ ] Preserve upstream response statuses, JSON keys, redirects, `Set-Cookie` behavior, and error codes.
- [ ] Run every route test file individually, then run the full core test suite.
- [ ] Add `.docs/features/base-auth-routes.md`.

## Phase 6: Plugin Contract

**Purpose:** Make optional features behave like upstream plugins rather than one-off Ruby modules.

**Files:**

- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/plugin.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/plugin_registry.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/plugin_context.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/plugin_test.rb`

Steps:

- [ ] Port upstream plugin behavior from `packages/core/src/types/plugin.ts`, `context/create-context.test.ts`, `api/check-endpoint-conflicts.test.ts`, and plugin helper tests.
- [ ] Implement plugin fields: `id`, `init`, `endpoints`, `middlewares`, `hooks`, `schema`, `migrations`, `options`, `rate_limit`, `error_codes`, `on_request`, `on_response`, `adapter`.
- [ ] Implement plugin init merging for options, context, and database hooks.
- [ ] Implement plugin endpoint merge after base endpoints.
- [ ] Implement plugin middlewares by path matcher.
- [ ] Implement plugin `before` and `after` endpoint hooks.
- [ ] Implement plugin schema merge into migration schema.
- [ ] Implement plugin error-code merge into auth error registry.
- [ ] Add tests for two plugins changing context, adding endpoints, adding schema, and changing endpoint responses through hooks.
- [ ] Add `.docs/features/plugin-system.md`.

## Phase 7: First Core Plugins

**Purpose:** Port small and foundational plugins before large B2B/protocol plugins.

**Order:**

1. `additional-fields`
2. `custom-session`
3. `multi-session`
4. `last-login-method`
5. `bearer`
6. `jwt`
7. `open-api`

Steps for each plugin:

- [ ] Add the plugin to the upstream parity matrix.
- [ ] Port the upstream plugin test file into `packages/better_auth/test/better_auth/plugins/<plugin>_test.rb`.
- [ ] Create the Ruby plugin under `packages/better_auth/lib/better_auth/plugins/<plugin>.rb`.
- [ ] Preserve upstream plugin options, schema fields, endpoint names, endpoint paths, error codes, hooks, and response shapes.
- [ ] Add or update `.docs/features/<plugin>.md`.
- [ ] Run that plugin's test file.
- [ ] Run related base route/session tests.

Completion criteria:

- [ ] All seven first core plugin test files pass.
- [ ] `bundle exec rake test` passes in `packages/better_auth`.

## Phase 8: Login And Identity Plugins

**Purpose:** Port user-facing login mechanisms after sessions and base auth are stable.

**Order:**

1. `username`
2. `anonymous`
3. `magic-link`
4. `email-otp`
5. `phone-number`
6. `one-time-token`
7. `one-tap`
8. `siwe`
9. `generic-oauth`
10. `oauth-proxy`
11. `passkey`

Steps for each plugin:

- [ ] Port upstream tests first.
- [ ] Implement plugin schema merge.
- [ ] Implement routes with exact upstream paths and method names.
- [ ] Implement client/server API aliases where upstream exposes them.
- [ ] Implement email/SMS/provider callback hooks as configurable Ruby callables.
- [ ] Preserve verification token expiry, callback URL behavior, trusted origin checks, and session cookie behavior.
- [ ] For passkeys, select Ruby WebAuthn dependency and document any unavoidable library-level differences.
- [ ] Add `.docs/features/<plugin>.md`.
- [ ] Run plugin tests and related route tests.

Completion criteria:

- [ ] Every login plugin has tests, docs, and parity matrix status.
- [ ] Demo-level flows can be reproduced through Rack requests.

## Phase 9: Security Plugins

**Purpose:** Port security-sensitive optional features with strict test parity.

**Order:**

1. `two-factor`
2. `captcha`
3. `haveibeenpwned`
4. `api-key`

Steps:

- [ ] Port `two-factor` tests covering TOTP, OTP, backup codes, trusted device cookies, enabling, disabling, and post-login verification.
- [ ] Implement two-factor schema and encrypted backup code handling.
- [ ] Port captcha tests and implement provider adapters for Google reCAPTCHA, hCaptcha, Cloudflare Turnstile, CaptchaFox.
- [ ] Port Have I Been Pwned tests and implement range API lookup with test stubs.
- [ ] Port API key tests and implement key creation, hashing, verification, expiration, usage limits, rate limit, metadata, storage modes, and API-key session behavior.
- [ ] Add feature docs for each security plugin.
- [ ] Run security plugin tests and full session tests after each plugin.

Completion criteria:

- [ ] Sensitive routes force authoritative session lookup where upstream does.
- [ ] Security plugin error codes match upstream.

## Phase 10: Organization, Access, Admin

**Purpose:** Port the core B2B surface.

**Files:**

- Create plugin modules under `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/plugins/organization/`
- Create plugin modules under `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/plugins/admin/`
- Create tests under `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/plugins/organization/`
- Create tests under `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/plugins/admin/`

Steps:

- [ ] Port upstream access tests and implement statements, roles, permission checks, and role inference.
- [ ] Port organization tests covering create, update, delete, list, active organization, slug checks, members, invitations, teams, active team, permissions, hooks, and client behavior.
- [ ] Implement organization schema: `organization`, `member`, `invitation`, optional `team`, optional `teamMember`, optional dynamic role tables, and session active organization fields.
- [ ] Preserve organization route paths from upstream route files.
- [ ] Port admin tests covering user list, create user, update user, remove user, roles, bans, impersonation, session listing, session revocation, and permission checks.
- [ ] Implement admin schema fields on user/session and hooks that enforce ban behavior.
- [ ] Add `.docs/features/access.md`, `.docs/features/organization.md`, and `.docs/features/admin.md`.
- [ ] Run organization/admin tests and all base auth route tests.

Completion criteria:

- [ ] Organization and admin flows work with memory adapter and are ready for SQL/Rails adapter mapping.

## Phase 11: OAuth, OIDC, Device Authorization, MCP

**Purpose:** Port protocol-heavy features after core auth and organization are stable.

**Order:**

1. `oidc-provider`
2. `oauth-provider`
3. `device-authorization`
4. `mcp`

Steps:

- [ ] Port OIDC provider tests for metadata, authorize, consent, token, userinfo, client registration, logout, prompt behavior, and schema.
- [ ] Port OAuth provider package tests from `upstream/packages/oauth-provider/src`.
- [ ] Preserve well-known endpoint behavior, issuer behavior, scopes, claims, access tokens, refresh tokens, consent, introspection, revoke, userinfo, client resource endpoints, and dynamic registration.
- [ ] Port device authorization tests for device code, user code, polling, approval, denial, expiry, and slow-down behavior.
- [ ] Port MCP tests for protected resource metadata, OAuth config, authorization, token, dynamic registration, and session helpers.
- [ ] Add docs for each protocol plugin with exact upstream references and Ruby dependency decisions.
- [ ] Run protocol tests individually and then as a group.

Completion criteria:

- [ ] OIDC/OAuth metadata and token endpoints are compatible enough for external clients in integration tests.

## Phase 12: Enterprise Packages And Integrations

**Purpose:** Port separate upstream packages that extend Better Auth.

**Order:**

1. `sso`
2. `scim`
3. `stripe`
4. `expo`

Steps:

- [ ] Decide whether each package lives inside `better_auth` as a plugin namespace or ships as a separate Ruby gem; document the decision before implementation.
- [ ] Port SSO tests for SAML, OIDC discovery, provider CRUD, domain verification, callbacks, ACS, metadata, and organization assignment.
- [ ] Port SCIM tests for tokens, service provider config, schemas, resource types, user CRUD, PATCH operations, filters, mappings, and auth middleware.
- [ ] Port Stripe tests for customer sync, organization mode, subscriptions, billing portal, webhooks, cancellation, restore, and plan behavior.
- [ ] Port Expo behavior into Rails/Rack-compatible mobile helpers only where Ruby server support applies: origin override, deep-link redirect cookie transfer, and authorization proxy.
- [ ] Add `.docs/features/sso.md`, `.docs/features/scim.md`, `.docs/features/stripe.md`, and `.docs/features/expo.md`.
- [ ] Run package-specific tests and document unsupported or deferred package boundaries if Ruby packaging differs.

Completion criteria:

- [ ] Enterprise feature docs clearly state parity status and installation/API shape.

## Phase 13: Rails Adapter

**Purpose:** Provide Rails ergonomics without leaking Rails into the core gem.

**Files:**

- Modify/create under `/Users/sebastiansala/projects/better-auth/packages/better_auth-rails/lib/better_auth/rails/`
- Create Rails specs under `/Users/sebastiansala/projects/better-auth/packages/better_auth-rails/spec/`

Steps:

- [ ] Implement Rails middleware or engine route mounting for `/api/auth/*`.
- [ ] Implement initializer generator for Better Auth configuration.
- [ ] Implement migration generator that reads core schema plus plugin schema.
- [ ] Implement ActiveRecord adapter that satisfies the core adapter contract.
- [ ] Implement controller helpers for current session, current user, authenticated checks, and route protection.
- [ ] Implement Rails cookie/CSRF compatibility behavior while delegating auth decisions to core.
- [ ] Add RSpec coverage for route mounting, initializer generation, migration generation, ActiveRecord adapter CRUD, cookies, sessions, and helpers.
- [ ] Update `packages/better_auth-rails/README.md`.
- [ ] Run `cd packages/better_auth-rails && bundle exec rspec`.
- [ ] Run workspace `make ci`.

Completion criteria:

- [ ] Rails adapter passes specs and no Rails dependency is introduced into `packages/better_auth`.

## Phase 14: Documentation, Examples, Release Readiness

**Purpose:** Make the port usable and maintainable.

Steps:

- [ ] Update root `README.md` with accurate port status.
- [ ] Update `packages/better_auth/README.md` with Rack quickstart, configuration, routes, plugins, and testing.
- [ ] Update `packages/better_auth-rails/README.md` with Rails quickstart, generator usage, routes, migrations, and helpers.
- [ ] Add a Rack/Sinatra example app if the repo structure allows examples.
- [ ] Add a Rails example app or dummy app for specs if needed.
- [ ] Maintain `.docs/features/upstream-parity-matrix.md` until every feature has a status.
- [ ] Add a release checklist covering `make ci`, gem build, changelog, version updates, and manual smoke flows.
- [ ] Run `make release-check`.

Completion criteria:

- [ ] Documentation explains what is complete, what differs from upstream, and how to validate a release.

## Feature Coverage List

The final Ruby port should cover these upstream product features:

- [ ] Core auth instance and handler.
- [ ] Server-side API calls.
- [ ] Email and password authentication.
- [ ] Social OAuth sign-in and callback flow.
- [ ] Session management and cookie cache.
- [ ] Password reset.
- [ ] Email verification.
- [ ] User update/delete.
- [ ] Account linking and unlinking.
- [ ] Access token refresh.
- [ ] Trusted origins and origin/CSRF protections.
- [ ] Rate limiting.
- [ ] Database adapters and schema generation/migration story.
- [ ] Secondary storage sessions.
- [ ] Hooks and database hooks.
- [ ] Plugin system.
- [ ] Client concept parity where server-side Ruby can expose equivalent API/docs.
- [ ] Username plugin.
- [ ] Anonymous plugin.
- [ ] Magic link plugin.
- [ ] Email OTP plugin.
- [ ] Phone number plugin.
- [ ] One-time token plugin.
- [ ] One tap plugin.
- [ ] SIWE plugin.
- [ ] Generic OAuth plugin.
- [ ] OAuth proxy plugin.
- [ ] Passkey plugin.
- [ ] Two-factor plugin.
- [ ] Captcha plugin.
- [ ] Have I Been Pwned plugin.
- [ ] API key plugin.
- [ ] Bearer plugin.
- [ ] JWT/JWKS plugin.
- [ ] Multi-session plugin.
- [ ] Custom session plugin.
- [ ] Last login method plugin.
- [ ] Additional fields plugin.
- [ ] OpenAPI plugin.
- [ ] Access control plugin.
- [ ] Organization plugin.
- [ ] Admin plugin.
- [ ] OIDC provider plugin.
- [ ] OAuth provider package behavior.
- [ ] Device authorization plugin.
- [ ] MCP plugin.
- [ ] SSO plugin.
- [ ] SCIM plugin.
- [ ] Stripe plugin.
- [ ] Expo/mobile server integration behavior.
- [ ] Rails adapter, generators, migrations, middleware, and helpers.

## Verification Commands

Use these commands as the default validation set:

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth
bundle exec rake test
bundle exec standardrb
```

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-rails
bundle exec rspec
bundle exec standardrb
```

```bash
cd /Users/sebastiansala/projects/better-auth
make ci
make release-check
```

Run narrower test files during feature work, but every completed phase should end with the relevant package-level suite.

## Assumptions And Defaults

- The TypeScript upstream submodule at `/Users/sebastiansala/projects/better-auth/upstream` is the source of truth.
- The initial upstream target is `better-auth` v1.4.22 on branch `v1.4.x`.
- Exact copy means exact public behavior where practical: route paths, JSON wire shape, cookies, error codes, option concepts, tests, docs, and feature semantics.
- Ruby internals may differ when the TypeScript implementation depends on TypeScript-only constructs, but differences must be documented in `.docs/features/*.md`.
- Core comes before Rails.
- Tests come before implementation.
- A feature is not complete until its docs, tests, and parity matrix entry are updated.
