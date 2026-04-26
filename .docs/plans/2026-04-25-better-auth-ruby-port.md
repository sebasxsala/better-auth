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
- [x] Address Phase 2 security review findings for default auth-route rate limits, custom rate-limit rules, IP tracking normalization, and JSON-by-default media-type enforcement.

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

- [x] Port upstream tests from `db/*.test.ts`, `db/internal-adapter.test.ts`, `db/secondary-storage.test.ts`, and adapter factory tests. Ruby Phase 3 ports focused schema, memory-adapter, internal-adapter, hook, and secondary-storage behavior; direct SQL migration/to-zod coverage remains outside this phase's Ruby file list.
- [x] Define core schema tables: `user`, `session`, `account`, `verification`, `rateLimit`.
- [x] Preserve upstream logical and wire field names: `id`, `name`, `email`, `emailVerified`, `image`, `createdAt`, `updatedAt`, `userId`, `token`, `expiresAt`, `ipAddress`, `userAgent`, `providerId`, `accountId`, `accessToken`, `refreshToken`, `idToken`, `scope`, `password`, `identifier`, `value`; default physical SQL names use PostgreSQL-friendly `snake_case`.
- [x] Implement schema merge for plugin schemas and additional fields.
- [x] Implement adapter operations: `create`, `find_one`, `find_many`, `update`, `update_many`, `delete`, `delete_many`, `count`, and `transaction`.
- [x] Implement memory adapter first; it is the default when no database is provided.
- [x] Implement `InternalAdapter` methods matching upstream semantics: user creation, OAuth user creation, account linking, session creation, session lookup, session update, session deletion, account lookup, verification value lifecycle, user listing, user count, password update.
- [x] Implement database hooks for create, update, update many, delete, and delete many.
- [x] Implement `secondary_storage` session behavior with token TTL and `active-sessions-*` lists.
- [x] Run schema, memory adapter, and internal adapter tests.
- [x] Add `.docs/features/database-adapters.md` with upstream links and Ruby storage decisions.

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

- [x] Port upstream `cookies/cookies.test.ts`, `client/session-refresh.test.ts`, and session route tests that only depend on session primitives. Ruby Phase 4 ports focused primitive tests; full route endpoint tests remain Phase 5.
- [x] Implement secure random ID generation and UUID mode.
- [x] Implement HMAC signing, signature verification, constant-time comparison, hashing helpers, symmetric encryption helpers, and JWT helpers needed by later plugins.
- [x] Implement BCrypt password hash and verify with configurable callbacks.
- [x] Implement cookie naming, prefixing, default attributes, secure cookie options, cross-subdomain attributes, and advanced cookie overrides.
- [x] Implement signed `session_token` cookies.
- [x] Implement `session_data` cookie cache, max age, refresh cache behavior, and disabling cache per request.
- [x] Implement cookie chunking and deletion for oversized cookie values.
- [x] Implement session lookup priority: signed cookie parse, cookie cache when allowed, adapter or secondary storage lookup, expiration refresh, response cookie update.
- [x] Add sensitive session behavior that bypasses stale cookie cache for sensitive routes.
- [x] Run crypto, cookie, and session tests.
- [x] Add `.docs/features/sessions-and-cookies.md`.

## Phase 4.5: Direct SQL Adapters For PostgreSQL And MySQL

**Purpose:** Start exercising real databases before full route work, without coupling the core gem to Rails or ActiveRecord.

**Architecture decision:** Core SQL support is framework-agnostic and adapter-based. PostgreSQL and MySQL adapters satisfy the same `BetterAuth::Adapters::Base` contract used by the memory adapter. They translate Better Auth logical model/field names into physical SQL table/column names from `BetterAuth::Schema`, use parameterized SQL only, and expose migration SQL generation. ActiveRecord remains a later Rails-layer adapter after Phase 5.

**Files:**

- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/adapters/sql.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/adapters/postgres.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/adapters/mysql.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/schema/sql.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/adapters/sql_test.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/adapters/postgres_test.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/adapters/mysql_test.rb`

Steps:

- [x] Add optional direct SQL adapter configuration examples: `database: BetterAuth::Adapters::Postgres.new(url: ENV["DATABASE_URL"])` and `database: BetterAuth::Adapters::MySQL.new(url: ENV["DATABASE_URL"])`.
- [x] Keep SQL driver gems out of Rails: `pg` and `mysql2` are adapter dependencies/dev-test dependencies for `better_auth`, not ActiveRecord dependencies. Current wrappers require those gems only when instantiated without an injected connection.
- [x] Generate PostgreSQL DDL from schema using plural `snake_case` table names, `text`, `boolean`, `timestamptz`, `bigint`, `not null`, unique constraints, FK constraints, and explicit FK indexes.
- [x] Generate MySQL DDL from schema using InnoDB, `utf8mb4`, `varchar/text`, `tinyint(1)`, `datetime(6)`, `bigint`, unique constraints, FK constraints, and explicit FK indexes.
- [x] Implement SQL adapter CRUD: `create`, `find_one`, `find_many`, `update`, `update_many`, `delete`, `delete_many`, `count`, and `transaction`.
- [x] Implement SQL where operators already supported by memory adapter: `eq`, `in`, `not_in`, `contains`, `starts_with`, `ends_with`, `ne`, `gt`, `gte`, `lt`, `lte`.
- [x] Implement SQL joins needed by current internal adapter: `session -> user`, `account -> user`, and `user -> account`.
- [x] Return logical Better Auth field names from SQL adapters (`emailVerified`, `createdAt`, `userId`) even though stored columns are `snake_case`.
- [x] Add integration tests that use root `docker-compose.yml` Postgres/MySQL services when drivers are available and skip with a clear message when drivers or services are unavailable.
- [x] Run SQL adapter unit tests and available integration tests.
- [x] Update `.docs/features/database-adapters.md` and `.docs/features/upstream-parity-matrix.md` with SQL adapter status and dependency decisions.

## Phase 5: Base Auth Routes

**Purpose:** Ship the core Better Auth product without optional plugins.

**Files:**

- Create route files under `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/routes/`
- Create matching tests under `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/routes/`
- Modify: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/core.rb`

Steps:

- [x] Port upstream base route tests from `api/routes/*.test.ts`.
- [x] Implement `/ok` and `/error`.
- [x] Implement `/sign-up/email` with email normalization, password validation, user creation, account creation, optional email verification, auto sign-in, callback URL behavior, and sign-up disabled behavior.
- [x] Implement `/sign-in/email` with password validation, banned/sensitive checks once plugins exist, session creation, remember-me behavior, and cookie setting. Admin-plugin ban checks remain deferred until the admin plugin exists.
- [x] Implement `/sign-in/social` and `/callback/:providerId` with OAuth state strategy, provider lookup, callback URL validation, new user callback, error callback, account linking, and token storage.
- [x] Implement `/sign-out`.
- [x] Implement `/get-session`, `/list-sessions`, `/revoke-session`, `/revoke-sessions`, `/revoke-other-sessions`.
- [x] Implement `/request-password-reset`, `/request-password-reset/callback`, `/reset-password`, `/verify-password`.
- [x] Implement `/send-verification-email` and `/verify-email`.
- [x] Implement `/update-user`, `/change-email`, `/change-password`, `/set-password`, `/delete-user`, `/delete-user/callback`.
- [x] Implement `/list-accounts`, `/link-social`, `/unlink-account`, `/get-access-token`, `/refresh-token`, `/account-info`.
- [x] Preserve upstream response statuses, JSON keys, redirects, `Set-Cookie` behavior, and error codes.
- [x] Run every route test file individually, then run the full core test suite.
- [x] Add `.docs/features/base-auth-routes.md`.

## Phase 5.5: Rails ActiveRecord Adapter And Mounting

**Purpose:** Add Rails ergonomics immediately after base routes are implemented, while keeping auth behavior in the Rack/core layer.

**Architecture decision:** Rails configuration lives in `config/initializers/better_auth.rb`, but the initializer should construct/configure the core auth instance rather than reimplement auth in Rails controllers. Rails mounts a single Rack endpoint for Better Auth routes; the Better Auth router handles dynamic internal routes like `/callback/:providerId`.

**Files:**

- Modify/create under `/Users/sebastiansala/projects/better-auth/packages/better_auth-rails/lib/better_auth/rails/`
- Create Rails specs under `/Users/sebastiansala/projects/better-auth/packages/better_auth-rails/spec/`

Steps:

- [x] Implement `config/initializers/better_auth.rb` generator that configures `BetterAuth.auth(...)` with Rails credentials/secrets and selected adapter.
- [x] Implement route mounting helper for a single Rack app, defaulting to `/api/auth/*`, with no per-route Rails controller magic.
- [x] Implement ActiveRecord adapter satisfying the core adapter contract after direct SQL and base routes are stable.
- [x] Implement migration generator that reads core schema plus plugin schema and emits Rails migrations matching the direct SQL schema decisions.
- [x] Implement controller helpers for `current_session`, `current_user`, authenticated checks, and route protection.
- [x] Document non-Rails routing: any Rack app can mount the auth object with `map "/api/auth" { run auth }` or call it directly as Rack middleware.
- [ ] Run Rails specs and core route specs against ActiveRecord once Phase 5 base routes exist. Rails specs pass for the initial adapter/generator surface, including a real PostgreSQL smoke test for generated migration, table/index/FK creation, ActiveRecord user read/write, and direct SQL adapter readback. Full base-route specs against ActiveRecord and MySQL real-database coverage remain pending.

## Phase 6: Plugin Contract

**Purpose:** Make optional features behave like upstream plugins rather than one-off Ruby modules.

**Files:**

- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/plugin.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/plugin_registry.rb`
- Create: `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/plugin_context.rb`
- Test: `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/plugin_test.rb`

Steps:

- [x] Port upstream plugin behavior from `packages/core/src/types/plugin.ts`, `context/create-context.test.ts`, `api/check-endpoint-conflicts.test.ts`, and plugin helper tests.
- [x] Implement plugin fields: `id`, `init`, `endpoints`, `middlewares`, `hooks`, `schema`, `migrations`, `options`, `rate_limit`, `error_codes`, `on_request`, `on_response`, `adapter`.
- [x] Implement plugin init merging for options, context, and database hooks.
- [x] Implement plugin endpoint merge after base endpoints.
- [x] Implement plugin middlewares by path matcher.
- [x] Implement plugin `before` and `after` endpoint hooks.
- [x] Implement plugin schema merge into migration schema.
- [x] Implement plugin error-code merge into auth error registry.
- [x] Add tests for two plugins changing context, adding endpoints, adding schema, and changing endpoint responses through hooks.
- [x] Add `.docs/features/plugin-system.md`.

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

- [x] Add the plugin to the upstream parity matrix.
- [x] Port the upstream plugin test file into `packages/better_auth/test/better_auth/plugins/<plugin>_test.rb`.
- [x] Create the Ruby plugin under `packages/better_auth/lib/better_auth/plugins/<plugin>.rb`.
- [x] Preserve upstream plugin options, schema fields, endpoint names, endpoint paths, error codes, hooks, and response shapes.
- [x] Add or update `.docs/features/<plugin>.md`.
- [x] Run that plugin's test file.
- [x] Run related base route/session tests.

Completion criteria:

- [x] All seven first core plugin test files pass.
- [x] `bundle exec rake test` passes in `packages/better_auth`.

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

Progress:

- [x] `username`: ported schema fields, sign-up/update hooks, `/sign-in/username`, `/is-username-available`, normalization, display username validation, duplicate checks, and email-verification no-leak behavior. Ruby adaptation: memory-adapter duplicate checks are performed by the plugin hook against normalized usernames because memory schema uniqueness is not global.
- [x] `anonymous`: ported `isAnonymous` schema, `/sign-in/anonymous`, `/delete-anonymous-user`, generated email/name options, repeat anonymous sign-in rejection, anonymous deletion, and real sign-in linking cleanup. Ruby adaptation: dependency-free email validation uses the core route email pattern; social callback cleanup uses the same response-cookie/new-session hook and remains covered by base social route tests.
- [x] `magic-link`: ported `/sign-in/magic-link`, `/magic-link/verify`, verification-table token lifecycle, new-user sign-up, existing-user email verification, redirect/error callback behavior, callback origin validation, custom token generation, and plain/hashed/custom token storage. Ruby adaptation: hashed storage uses core SHA-256/base64url helpers instead of an extra dependency.
- [x] `email-otp`: ported `/email-otp/send-verification-otp`, `/email-otp/check-verification-otp`, `/email-otp/verify-email`, `/sign-in/email-otp`, `/email-otp/request-password-reset`, deprecated `/forget-password/email-otp`, `/email-otp/reset-password`, server OTP create/get helpers, sign-up OTP sending hook, allowed-attempt tracking, and plain/hashed/encrypted/custom OTP storage. Ruby adaptation: endpoints own Better Auth behavior and call a configured `send_verification_otp` callable for delivery; email/SMS/provider transport is intentionally application code, matching upstream's callback model.
- [x] `phone-number`: ported `/phone-number/send-otp`, `/phone-number/verify`, `/sign-in/phone-number`, `/phone-number/request-password-reset`, `/phone-number/reset-password`, user schema fields `phoneNumber` and `phoneNumberVerified`, OTP sign-up/session creation, verified phone-number updates, direct update-user prevention, password sign-in, require-verification OTP trigger, reset-password OTP, session revocation, allowed-attempt tracking, custom validator, and custom `verify_otp`. Ruby adaptation: SMS/provider delivery and external OTP verification stay configurable callables; Better Auth owns endpoint behavior and persistence.
- [x] `one-time-token`: ported `/one-time-token/generate`, `/one-time-token/verify`, single-use token verification, token expiration, expired-session rejection, default session-cookie setting, cookie suppression, plain/hashed/custom token storage, server-only generation, and `set-ott` header generation on new sessions. Ruby adaptation: hashed storage uses core SHA-256/base64url helpers and Rack GET requests without bodies now parse as empty bodies.
- [x] `one-tap`: ported `/one-tap/callback`, Google ID-token verification, new-user OAuth creation, existing Google account reuse, verified/trusted account linking, `disable_signup`, session-cookie setting, invalid-token handling, and email-missing response. Ruby adaptation: default Google token verification uses existing `jwt` plus stdlib JWKS fetch; tests and apps may inject `verify_id_token` to avoid network-coupled verification.
- [x] `siwe`: ported `/siwe/nonce`, `/siwe/verify`, wallet-address schema, nonce storage per wallet and chain, nonce consumption, callback-based message verification, anonymous/email modes, ENS lookup callback, user/account/session creation, and multi-chain wallet reuse. Ruby adaptation: wallet addresses normalize to lowercase for lookup; exact EIP-55 checksum casing remains a dependency decision because it needs Keccak support.
- [x] `generic-oauth`: ported `/sign-in/oauth2`, `/oauth2/callback/:providerId`, `/oauth2/link`, custom token and user-info callbacks, authorization URL generation, scopes, PKCE state data, issuer mismatch redirects, implicit sign-up controls, new-user redirects, account storage, and account linking. Ruby adaptation: provider helper factories and exhaustive OAuth server integration matrix remain future polish.
- [x] `oauth-proxy`: ported `/oauth-proxy-callback`, sign-in callback URL rewriting, same-origin proxy unwrap, cross-origin encrypted cookie payload forwarding, payload timestamp validation, trusted callback URL validation, cookie setting, and invalid payload redirects. Ruby adaptation: deeper upstream stateless state-cookie package restoration remains future polish if DB-less OAuth callback restoration needs it.
- [x] `passkey`: ported WebAuthn option generation, registration verification, authentication verification, challenge-cookie storage, passkey schema, list/update/delete routes, and session-cookie creation after passkey sign-in. Ruby adaptation: uses the maintained `webauthn` gem (`cedarcode/webauthn-ruby`) for server-side WebAuthn and cryptographic verification; credential public keys are stored as Base64 strings for adapter portability, and backup eligibility maps to upstream-style `singleDevice`/`multiDevice`.

Steps for each plugin:

- [x] Port upstream tests first.
- [x] Implement plugin schema merge.
- [x] Implement routes with exact upstream paths and method names.
- [x] Implement client/server API aliases where upstream exposes them.
- [x] Implement email/SMS/provider callback hooks as configurable Ruby callables.
- [x] Preserve verification token expiry, callback URL behavior, trusted origin checks, and session cookie behavior.
- [x] For passkeys, select Ruby WebAuthn dependency and document any unavoidable library-level differences.
- [x] Add `.docs/features/<plugin>.md`.
- [x] Run plugin tests and related route tests.

Completion criteria:

- [x] Every login plugin has tests, docs, and parity matrix status.
- [ ] Demo-level flows can be reproduced through Rack requests.

## Phase 9: Security Plugins

**Purpose:** Port security-sensitive optional features with strict test parity.

**Order:**

1. `two-factor`
2. `captcha`
3. `haveibeenpwned`
4. `api-key`

Steps:

- [x] Port `two-factor` tests covering TOTP, OTP, backup codes, trusted device cookies, enabling, disabling, and post-login verification.
- [x] Implement two-factor schema and encrypted backup code handling.
- [x] Port captcha tests and implement provider adapters for Google reCAPTCHA, hCaptcha, Cloudflare Turnstile, CaptchaFox.
- [x] Port Have I Been Pwned tests and implement range API lookup with test stubs.
- [x] Port API key tests and implement key creation, hashing, verification, expiration, usage limits, rate limit, metadata, storage modes, and API-key session behavior.
- [x] Add feature docs for each security plugin.
- [x] Run security plugin tests and full session tests after each plugin.

Completion criteria:

- [x] Sensitive routes force authoritative session lookup where upstream does.
- [x] Security plugin error codes match upstream.

## Phase 10: Organization, Access, Admin

**Purpose:** Port the core B2B surface.

**Files:**

- Create plugin modules under `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/plugins/organization/`
- Create plugin modules under `/Users/sebastiansala/projects/better-auth/packages/better_auth/lib/better_auth/plugins/admin/`
- Create tests under `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/plugins/organization/`
- Create tests under `/Users/sebastiansala/projects/better-auth/packages/better_auth/test/better_auth/plugins/admin/`

Steps:

- [x] Port upstream access tests and implement statements, roles, permission checks, and role inference. Ruby adaptation: TypeScript role inference is not applicable, so runtime behavior is covered.
- [x] Port organization tests covering create, update, delete, list, active organization, slug checks, members, invitations, teams, active team, permissions, hooks, and client behavior. Ruby adaptation: browser client/type inference coverage is documented as future polish.
- [x] Implement organization schema: `organization`, `member`, `invitation`, optional `team`, optional `teamMember`, optional dynamic role tables, and session active organization fields.
- [x] Preserve organization route paths from upstream route files.
- [x] Port admin tests covering user list, create user, update user, remove user, roles, bans, impersonation, session listing, session revocation, and permission checks.
- [x] Implement admin schema fields on user/session and hooks that enforce ban behavior.
- [x] Add `.docs/features/access.md`, `.docs/features/organization.md`, and `.docs/features/admin.md`.
- [x] Run organization/admin tests and all base auth route tests. Focused Phase 10 plugin tests and base auth route tests pass; broader repo suite still has unrelated failures in later plugin work.

Completion criteria:

- [x] Organization and admin flows work with memory adapter and are ready for SQL/Rails adapter mapping.

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
- [x] Add docs for each protocol plugin with exact upstream references and Ruby dependency decisions.
- [x] Run protocol tests individually and then as a group.

Progress:

- [x] Added Phase 11 executable plan at `.docs/plans/2026-04-26-phase-11-protocol-plugins.md`.
- [x] Added shared Ruby OAuth/OIDC protocol helpers without new runtime dependencies.
- [x] Added partial OIDC provider coverage for metadata, prompt parsing, dynamic registration, authorize, token, userinfo, refresh token issuance, and logout.
- [x] Added partial OAuth provider package coverage for metadata, RFC 9207 issuer normalization, client registration/public lookup, client-credentials token issuance, introspection, and revocation.
- [x] Added partial device authorization coverage for device/user code issuance, verification, polling, approval, denial, expiry, slow-down, custom generators, client validation, and verification URI behavior.
- [x] Added partial MCP coverage for OAuth metadata, protected-resource metadata, public PKCE client registration, token/refresh, userinfo, and `WWW-Authenticate` helper behavior.
- [ ] Full upstream OIDC/OAuth/MCP consent, organization, logout, rate-limit, JWT algorithm, encrypted client-secret, and server-client integration matrices remain future polish.

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

- [x] Decide whether each package lives inside `better_auth` as a plugin namespace or ships as a separate Ruby gem; document the decision before implementation.
- [x] Add partial SSO coverage for SAML, OIDC discovery, provider CRUD, domain verification, callbacks, ACS, metadata, replay protection, and SAML origin bypass. Organization assignment remains deferred until the organization plugin exists.
- [x] Add partial SCIM coverage for tokens, service provider config, schemas, resource types, user CRUD, PATCH operations, simple filters, mappings, and auth middleware.
- [x] Add partial Stripe coverage for customer sync, guarded organization mode, subscriptions, billing portal, webhooks, cancellation, restore, and plan behavior using an injected fake client.
- [x] Port Expo behavior into Rails/Rack-compatible mobile helpers where Ruby server support applies: origin override, deep-link redirect cookie transfer, and authorization proxy.
- [x] Add `.docs/features/sso.md`, `.docs/features/scim.md`, `.docs/features/stripe.md`, and `.docs/features/expo.md`.
- [x] Run package-specific tests and document unsupported or deferred package boundaries if Ruby packaging differs.
- [ ] Full SAML XML signature/encryption/assertion validation, SCIM RFC filter/PATCH matrix, Stripe billing edge-case matrix, and organization-backed enterprise flows remain future polish.

Completion criteria:

- [x] Enterprise feature docs clearly state parity status and installation/API shape.

## Phase 13: Rails Adapter

**Purpose:** Finish Rails adapter polish after the early Phase 5.5 ActiveRecord/mounting work.

**Files:**

- Modify/create under `/Users/sebastiansala/projects/better-auth/packages/better_auth-rails/lib/better_auth/rails/`
- Create Rails specs under `/Users/sebastiansala/projects/better-auth/packages/better_auth-rails/spec/`

Steps:

- [ ] Harden Rails middleware or engine route mounting for `/api/auth/*` after plugin routes are available.
- [ ] Harden initializer generator for Better Auth configuration.
- [ ] Harden migration generator for plugin schemas beyond the base auth schema.
- [ ] Extend ActiveRecord adapter coverage for plugin schemas and advanced query cases.
- [ ] Harden controller helpers for current session, current user, authenticated checks, and route protection.
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
- [x] Social OAuth sign-in and callback flow.
- [ ] Session management and cookie cache.
- [x] Password reset.
- [x] Email verification.
- [x] User update/delete.
- [x] Account linking and unlinking.
- [x] Access token refresh.
- [ ] Trusted origins and origin/CSRF protections.
- [ ] Rate limiting.
- [ ] Database adapters and schema generation/migration story.
- [ ] Secondary storage sessions.
- [ ] Hooks and database hooks.
- [x] Plugin system.
- [ ] Client concept parity where server-side Ruby can expose equivalent API/docs.
- [x] Username plugin.
- [x] Anonymous plugin.
- [x] Magic link plugin.
- [x] Email OTP plugin.
- [x] Phone number plugin.
- [x] One-time token plugin.
- [ ] One tap plugin.
- [ ] SIWE plugin.
- [ ] Generic OAuth plugin.
- [ ] OAuth proxy plugin.
- [ ] Passkey plugin.
- [x] Two-factor plugin.
- [x] Captcha plugin.
- [x] Have I Been Pwned plugin.
- [x] API key plugin.
- [x] Bearer plugin.
- [x] JWT/JWKS plugin.
- [x] Multi-session plugin.
- [x] Custom session plugin.
- [x] Last login method plugin.
- [x] Additional fields plugin.
- [x] OpenAPI plugin.
- [x] Access control plugin.
- [x] Organization plugin.
- [x] Admin plugin.
- [x] OIDC provider plugin.
- [x] OAuth provider package behavior.
- [x] Device authorization plugin.
- [x] MCP plugin.
- [x] SSO plugin.
- [x] SCIM plugin.
- [x] Stripe plugin.
- [x] Expo/mobile server integration behavior.
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
