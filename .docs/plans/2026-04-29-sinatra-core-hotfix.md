# Better Auth Sinatra/Core Hotfix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` or `executing-plans` to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Fix focused Sinatra adapter and core auth regressions found during review.

**Architecture:** Keep framework integration fixes in `packages/better_auth-sinatra` and core auth behavior fixes in `packages/better_auth`. Add failing regression tests before each behavior change, then implement the minimum fix needed to pass.

**Tech Stack:** Ruby 3.4.9, Rack, Sinatra, RSpec, Minitest, StandardRB.

---

## Tasks

- [x] Create/switch to `codex/sinatra-core-hotfix` from the current detached commit.
- [x] Add Sinatra regression tests for helper session isolation, base path override handling, and migration dialect env aliases.
- [x] Implement Sinatra fixes for request runtime reset, mount path precedence, and dialect normalization.
- [x] Add core regression tests for OAuth PKCE state, trusted callback redirects, change-email verification, and stale delete-user sessions.
- [x] Implement core fixes in routes/session, social, email verification, user, and password callback handling.
- [x] Run targeted Sinatra and core route tests.
- [x] Run StandardRB checks with sandbox-safe cache roots.
- [x] Record any verification limitations.

## Verification

- [x] `cd packages/better_auth-sinatra && rbenv exec bundle exec rspec`
- [x] `cd packages/better_auth-sinatra && RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache_sinatra rbenv exec bundle exec standardrb`
- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/routes/social_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/routes/email_verification_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/routes/user_routes_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/routes/password_test.rb`

Full `packages/better_auth` test suite was not rerun in this pass because the earlier run reached known local service/sandbox blockers: MySQL/Postgres/MSSQL services and local TCP binding for OAuth server tests.
