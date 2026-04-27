# Better Auth Hanami Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `test-driven-development` while implementing this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a first-class Hanami 2.3+ integration gem at `packages/better_auth-hanami`.

**Architecture:** Keep Better Auth behavior in the Rack/core gem. The Hanami gem provides configuration, route mounting, a Sequel/ROM-backed adapter, ROM::SQL migration generation, action helpers, docs, and stable Rake/generator commands.

**Tech Stack:** Ruby 3.2+, Better Auth core, Hanami 2.3+, Rack 3, Sequel/ROM::SQL, RSpec, StandardRB.

---

## Tasks

- [x] Scaffold `packages/better_auth-hanami` using the Rails adapter package shape.
- [x] Add failing specs for configuration, route mounting, migration rendering, Sequel persistence, helper behavior, generators, and Rack route flows.
- [x] Implement `BetterAuth::Hanami.configure`, `.configuration`, and `.auth`.
- [x] Implement `BetterAuth::Hanami::Routing` and `MountedApp` for Hanami route mounting.
- [x] Implement `BetterAuth::Hanami::SequelAdapter` against Hanami's ROM/Sequel gateway.
- [x] Implement `BetterAuth::Hanami::Migration.render` for ROM::SQL migrations.
- [x] Implement install, migration, and relation/repo generators plus Rake task wrappers.
- [x] Implement action helpers for `current_session`, `current_user`, `authenticated?`, and `require_authentication`.
- [x] Add `packages/better_auth-hanami/README.md`, `.docs/features/hanami-adapter.md`, and `docs/content/docs/integrations/hanami.mdx`.
- [x] Update workspace Rake/Make tasks to include `better_auth-hanami`.

## Verification

- [x] `cd packages/better_auth-hanami && rbenv exec bundle exec rspec`
- [x] `cd packages/better_auth-hanami && RUBOCOP_CACHE_ROOT=/private/var/folders/7x/jrsz946d2w73n42fb1_ff5000000gn/T/rubocop_cache_hanami rbenv exec bundle exec standardrb`
- [ ] `cd packages/better_auth && rbenv exec bundle exec rake test` blocked locally because Bundler cannot find/build the `mysql2` development dependency without local MySQL client libraries.
- [x] `cd packages/better_auth-rails && rbenv exec bundle exec rspec` passed when run outside the sandbox so PostgreSQL localhost access is permitted.

## Assumptions And Limits

- Hanami 2.3+ only. Hanami 1.x and Hanami 2.2/Rack 2 are out of scope because Better Auth core uses Rack 3.
- Stable commands are Rake/generator based. The public Hanami 2.3 guides document app commands, routes, providers, settings, and DB migrations, but not a stable third-party CLI extension API for `hanami better_auth ...`.
- The adapter generates Hanami relations and repos for app-level queries, but Better Auth still owns auth writes through its adapter contract.
- Apps created with `--skip-db` may use memory mode for development/tests, but production persistence requires Hanami DB or an explicit adapter.
