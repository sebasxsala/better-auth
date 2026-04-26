# Phase 13 Rails Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` when the work can be split into independent tasks, or `executing-plans` when implementing sequentially in one session. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the Rails adapter so Rails apps can mount Better Auth reliably, generate migrations for plugin schemas, use ActiveRecord for core and plugin models, and expose ergonomic controller helpers without moving auth decisions out of core.

**Architecture:** Rails remains a thin integration layer around the framework-agnostic core Rack auth object. The adapter wraps Rails mounting/path behavior, renders Rails migrations from `BetterAuth::Schema`, maps ActiveRecord models to Better Auth logical fields, and exposes controller helpers that call core session lookup.

**Tech Stack:** Ruby 3.3 through `rbenv`, Rails/Railties/ActiveRecord, Rack, RSpec, StandardRB, PostgreSQL integration specs, and upstream Better Auth TypeScript sources under `upstream/`.

---

## Upstream References

- Runtime/mounting shape: `upstream/packages/better-auth/src/integrations/node.ts`, `upstream/packages/better-auth/src/integrations/next-js.ts`
- Origin/CSRF behavior: `upstream/packages/better-auth/src/api/middlewares/origin-check.ts`, `upstream/packages/better-auth/src/api/middlewares/origin-check.test.ts`
- Schema/migration behavior: `upstream/packages/better-auth/src/db/schema.ts`, `upstream/packages/better-auth/src/db/get-schema.ts`, `upstream/packages/better-auth/src/db/get-migration.ts`, `upstream/packages/better-auth/src/db/get-migration-schema.test.ts`
- Adapter contract/tests: `upstream/packages/better-auth/src/adapters/tests/basic.ts`, `upstream/packages/better-auth/src/adapters/tests/joins.ts`, `upstream/packages/better-auth/src/adapters/tests/transactions.ts`, `upstream/packages/better-auth/src/adapters/tests/auth-flow.ts`
- Plugin schemas: `upstream/packages/better-auth/src/plugins/*/schema.ts`, plugin `*.test.ts`

## Tasks

- [x] Harden route mounting in `packages/better_auth-rails/lib/better_auth/rails/routing.rb` so `better_auth` mounts one Rack auth app at configurable paths, preserves plugin routes, and works when Rails strips the mount prefix into `SCRIPT_NAME`.
- [x] Harden `packages/better_auth-rails/lib/better_auth/rails/configuration.rb` and the install initializer template so Rails secrets, `BETTER_AUTH_URL`, plugins, trusted origins, hooks, and ActiveRecord adapter config round-trip into `BetterAuth.auth`.
- [x] Extend `packages/better_auth-rails/lib/better_auth/rails/migration.rb` and generator specs so plugin schemas generate Rails migrations for extra fields and new plugin tables, including nullable refs, defaults, indexes, uniqueness, timestamps, and foreign keys.
- [x] Expand ActiveRecord adapter specs to cover upstream adapter contract cases: plugin models, additional fields, default values, `select`, `sort_by`, `limit`, `offset`, where operators, joins, `update_many(returning:)`, transactions, and logical-to-physical field mapping.
- [x] Add Rails request/controller specs for `current_session`, `current_user`, `authenticated?`, and `require_authentication`, while keeping all auth decisions delegated to core `BetterAuth::Session.find_current`.
- [x] Add Rails cookie/CSRF compatibility coverage: Rails request cookies flow into core, core `Set-Cookie` survives mounted Rack responses, mutating requests still rely on core origin/CSRF checks, and Rails helpers never bypass core auth.
- [x] Update `packages/better_auth-rails/README.md` and `.docs/features/rails-adapter.md` with Rails quickstart, generator usage, plugin schema migration examples, route mounting, helpers, and verification commands.
- [x] Update `.docs/plans/2026-04-25-better-auth-ruby-port.md` Phase 13 checkboxes as work completes.

## Verification

- [x] `cd packages/better_auth-rails && rbenv exec bundle exec rspec`
- [x] `cd packages/better_auth-rails && RUBOCOP_CACHE_ROOT=/private/var/folders/7x/jrsz946d2w73n42fb1_ff5000000gn/T/rubocop_cache_rails rbenv exec bundle exec standardrb`
- [x] `cd packages/better_auth && rbenv exec bundle exec rake test`
- [x] `make ci` from repo root after Rails and core suites pass.

## Assumptions

- Rails-specific code stays entirely inside `packages/better_auth-rails`; no Rails or ActiveRecord dependencies are introduced into `packages/better_auth`.
- Rails mounts the core Rack auth object through an adapter wrapper; Rails controllers do not reimplement Better Auth routes.
- Use `rbenv exec` for Ruby commands in this workspace because plain `bundle exec` resolves to system Ruby and fails on Bundler 2.5.22.
