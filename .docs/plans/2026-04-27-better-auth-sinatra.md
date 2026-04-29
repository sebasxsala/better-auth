# Better Auth Sinatra Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` when the work can be split into independent tasks, or `executing-plans` when implementing sequentially in one session. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `better_auth-sinatra` gem that gives Sinatra apps first-class Better Auth mounting, helpers, SQL migrations, docs, and tests while keeping authentication behavior in the Rack/core gem.

**Architecture:** Sinatra remains a thin integration layer around `BetterAuth.auth`. The package registers a Sinatra extension, mounts the core Rack auth object at `/api/auth` by default, exposes request helpers that call core session lookup, and uses the existing core SQL schema renderer/adapters for migrations. ActiveRecord is intentionally not a runtime dependency in the first version.

**Tech Stack:** Ruby 3.2+, Sinatra 3/4, Rack 3, Rack::Test, RSpec, Rake, StandardRB, core `better_auth` SQL adapters, and upstream Better Auth integration/schema sources under `upstream/`.

---

## Tasks

- [x] Scaffold `packages/better_auth-sinatra/` with gemspec, Gemfile, Rakefile, README, changelog, license, package `AGENTS.md`, version file, and require aliases.
- [x] Add `BetterAuth::Sinatra::Configuration`, `.configure`, `.configuration`, `.auth`, and `.reset!`, mirroring the Rails option pass-through but without a default ActiveRecord adapter.
- [x] Add a Sinatra extension API: `register BetterAuth::Sinatra` plus `better_auth at: "/api/auth" do |config| ... end`.
- [x] Add a mounted Rack wrapper that delegates matching Better Auth paths to the core auth object while preserving the full request path expected by the core router.
- [x] Add helpers: `current_session`, `current_user`, `authenticated?`, and `require_authentication`, caching session data in `request.env["better_auth.session"]` and halting unauthenticated Sinatra requests with `401`.
- [x] Add SQL migration rendering and execution for core SQL adapters using `BetterAuth::Schema::SQL.create_statements`, pending SQL files under `db/better_auth/migrate`, and a `better_auth_schema_migrations` ledger.
- [x] Add Rake tasks: `better_auth:install`, `better_auth:generate:migration`, `better_auth:migrate`, and `better_auth:routes`.
- [x] Document limitations: Sinatra has no Rails-like built-in generator/migration command, v1 does not support ActiveRecord-backed Sinatra migrations, memory/Mongo/custom adapters cannot run SQL migrations, and apps must explicitly register the extension or middleware.
- [x] Add docs in `docs/content/docs/integrations/sinatra.mdx`, update Ruby/Rack docs, root README, feature notes, CI, release workflow, Makefile, Rakefile, and root Gemfile.
- [x] Update `.docs/plans/2026-04-25-better-auth-ruby-port.md` with a Sinatra adapter phase and keep this plan's checkboxes current.

## Verification

- [x] `cd packages/better_auth-sinatra && rbenv exec bundle exec rspec`
- [x] `cd packages/better_auth-sinatra && RUBOCOP_CACHE_ROOT=/private/var/folders/7x/jrsz946d2w73n42fb1_ff5000000gn/T/rubocop_cache_sinatra rbenv exec bundle exec standardrb`
- [x] `cd packages/better_auth-sinatra && RUBOCOP_CACHE_ROOT=/private/var/folders/7x/jrsz946d2w73n42fb1_ff5000000gn/T/rubocop_cache_sinatra rbenv exec bundle exec rake ci`
- [x] `cd packages/better_auth-sinatra && rbenv exec gem build better_auth-sinatra.gemspec`
- [ ] `cd packages/better_auth && rbenv exec bundle exec rake test` (blocked locally by missing MySQL/FreeTDS native headers for `mysql2` and `tiny_tds`; focused non-Bundler core auth/router tests pass)
- [x] `cd packages/better_auth && rbenv exec ruby -Ilib:test test/better_auth/auth_test.rb`
- [x] `cd packages/better_auth && rbenv exec ruby -Ilib:test test/better_auth/router_test.rb`
- [x] `ruby -e 'require "yaml"; YAML.load_file(".github/workflows/ci.yml"); YAML.load_file(".github/workflows/release.yml")'`
- [x] `ruby -e 'require "json"; JSON.parse(File.read("docs/content/docs/meta.json"))'`
- [x] `git diff --check`
- [ ] `make ci` after package-level suites pass.

## Assumptions And Limits

- Sinatra itself does not provide a built-in SQL adapter or a universal `rails db:migrate` equivalent. This package provides Better Auth-specific Rake tasks.
- `sinatra-activerecord` can be documented as a future/optional path, but `better_auth-sinatra` v1 uses core SQL adapters and does not depend on ActiveRecord.
- No Sinatra code belongs in `packages/better_auth`; the core gem remains Rack/framework agnostic.
