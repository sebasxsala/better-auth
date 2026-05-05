# Better Auth Core Audit And Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Audit `packages/better_auth` against upstream Better Auth `v1.6.9`, then implement the highest-value core hardening and documentation corrections found.

**Architecture:** Keep the Ruby core framework-agnostic and Rack-only. Use upstream TypeScript source and tests as the behavior oracle, but adapt to existing Ruby primitives, Minitest, and the current package boundaries.

**Tech Stack:** Ruby, Rack, Minitest, StandardRB, upstream Better Auth TypeScript sources in `upstream/`.

---

## Task 1: Baseline And Audit Map

**Files:**
- Read: `AGENTS.md`
- Read: `packages/better_auth/AGENTS.md`
- Read: `upstream/packages/better-auth/src/**`
- Read: `upstream/packages/core/src/**`
- Modify: `.docs/plans/2026-05-04-2209--better-auth-core-audit-hardening.md`

- [x] Confirm upstream is initialized and checked to a `1.6.9` tag or compatible `1.6.9` package tag.
- [x] Run baseline core tests with `cd packages/better_auth && rbenv exec bundle exec rake test`.
- [x] Run baseline lint with `cd packages/better_auth && rbenv exec bundle exec standardrb`.
- [x] Inventory server-visible upstream route/plugin/provider coverage.
- [x] Record focused findings in this plan before implementing fixes.

## Task 2: Parity Documentation Corrections

**Files:**
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `.docs/features/core-auth-api.md`
- Modify: `.docs/features/endpoint-router-api.md`

- [x] Update the parity matrix source-of-truth version from `v1.4.22` to `v1.6.9`.
- [x] Correct stale rows where current Ruby code is ahead of the old matrix, including core auth/router/API, database-backed rate limits, OAuth/social/account routes, and social provider inventory.
- [x] Keep incomplete areas marked `Partial` when upstream parity is not exact or not fully documented.

## Task 3: OpenAPI Base Route Hardening

**Files:**
- Modify: `packages/better_auth/test/better_auth/plugins/open_api_test.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/*.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/open_api.rb` only if route metadata alone cannot express the upstream shape.

- [x] Compare current Ruby OpenAPI output with upstream `upstream/packages/better-auth/src/plugins/open-api/__snapshots__/open-api.test.ts.snap`.
- [x] Add failing Minitest coverage for the highest-value missing base-route request/response metadata.
- [x] Add route metadata or generator support to pass the new tests without changing route behavior.
- [x] Re-run the focused OpenAPI test file.

## Task 4: OAuth/Social/Account Route Gap Tests

**Files:**
- Modify: `packages/better_auth/test/better_auth/routes/social_test.rb`
- Modify: `packages/better_auth/test/better_auth/routes/account_test.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/social.rb` or `packages/better_auth/lib/better_auth/routes/account.rb` only for confirmed failures.

- [x] Compare upstream account/social tests with Ruby route tests.
- [x] Add one or more upstream-style tests for a missing high-value edge case.
- [x] Implement minimal code only if a new test exposes a real behavior gap.
- [x] Re-run the focused route test files.

## Task 5: Verification And Final Notes

**Files:**
- Modify: `.docs/plans/2026-05-04-2209--better-auth-core-audit-hardening.md`

- [x] Run `cd packages/better_auth && rbenv exec bundle exec rake test`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec standardrb`.
- [x] Update this plan with completed checkboxes, meaningful upstream differences, Ruby-specific adaptations, and any deferred gaps.
- [x] Confirm no Rails/Sinatra/Hanami code was added to `packages/better_auth`.

## Focused Audit Findings

- Upstream is checked out at `@better-auth/api-key@1.6.9` on commit `f48426922`; this is a compatible monorepo package tag for the target `v1.6.9` source.
- Baseline core verification before edits passed: `822 runs, 4336 assertions, 0 failures, 0 errors, 0 skips`; `standardrb` also passed.
- Core coverage is ahead of stale docs: the Ruby package now has real base routes, direct API calls, Rack routing, context runtime handling, request state, plugin ordering, database-backed rate limits, OAuth/social/account flows, and all 35 upstream core social provider factories.
- The parity matrix still must keep several core rows `Partial`: upstream auth/context/API/client typing and every route edge case are broader than the current Ruby server test matrix.
- Confirmed OpenAPI gap from `upstream/packages/better-auth/src/plugins/open-api/open-api.test.ts`: `/get-session` should use OpenAPI 3.1 nullable type arrays (`type: ["object", "null"]`) instead of legacy `nullable: true`. Ruby route metadata was updated without changing runtime route behavior.
- Account/social audit found the upstream provider `accountId` bug case already covered by `packages/better_auth/test/better_auth/routes/account_test.rb`. Added route coverage for upstream-style custom `scopes` forwarding in `link_social`.

## Focused Verification

- `rbenv exec bundle exec ruby -Itest test/better_auth/plugins/open_api_test.rb --name test_open_api_uses_upstream_31_nullable_get_session_response_shape`: failed before implementation with `Expected: ["object", "null"], Actual: "object"`.
- `rbenv exec bundle exec ruby -Itest test/better_auth/plugins/open_api_test.rb --name test_open_api_uses_upstream_31_nullable_get_session_response_shape`: passed after route metadata change.
- `rbenv exec bundle exec ruby -Itest test/better_auth/plugins/open_api_test.rb`: `19 runs, 386 assertions, 0 failures, 0 errors, 0 skips`.
- `rbenv exec bundle exec ruby -Itest test/better_auth/routes/social_test.rb`: `36 runs, 123 assertions, 0 failures, 0 errors, 0 skips`.
- `rbenv exec bundle exec ruby -Itest test/better_auth/routes/account_test.rb`: `20 runs, 80 assertions, 0 failures, 0 errors, 0 skips`.
- `rbenv exec bundle exec rake test`: `825 runs, 4348 assertions, 0 failures, 0 errors, 0 skips`.
- `rbenv exec bundle exec standardrb`: passed.
