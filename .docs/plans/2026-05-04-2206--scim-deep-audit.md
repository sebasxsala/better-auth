# SCIM Deep Audit Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement follow-up tasks. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record an evidence-backed audit of `better_auth-scim`, its upstream parity, and the highest-value hardening work left to do.

**Architecture:** `better_auth-scim` is a Ruby plugin package that mirrors upstream `@better-auth/scim` behavior through Better Auth plugin endpoints, schema additions, token middleware, SCIM resource mappers, filter parsing, and patch operation helpers. The audit produced follow-up tasks; this plan now tracks their implementation.

**Tech Stack:** Ruby 3.2+, Better Auth Ruby plugin APIs, Minitest, StandardRB, upstream Better Auth SCIM TypeScript source under `upstream/packages/scim`.

---

## Audit Checklist

- [x] Read root `AGENTS.md`.
- [x] Confirm no package-level `AGENTS.md` exists for `packages/better_auth-scim`.
- [x] Compare Ruby SCIM behavior with upstream routes, middleware, token storage, filters, patch operations, schemas, mappings, and tests.
- [x] Identify intentional Ruby adaptations versus possible parity gaps.
- [x] Review security and correctness risks around token lookup/verification, provider ownership, org scoping, hook failure behavior, duplicate account/provider races, and SCIM error shapes.
- [x] Review maintainability risks around route file size, validation placement, adapter assumptions, docs drift, and test coverage.
- [x] Produce prioritized follow-up tasks with exact files, expected behavior, public API impact, and test commands.

## Baseline Evidence

- `cd packages/better_auth-scim && rbenv exec bundle exec rake test`
  - Result: `41 runs, 341 assertions, 0 failures, 0 errors, 0 skips`.
- `cd packages/better_auth-scim && rbenv exec bundle exec standardrb`
  - Result: passed with no output.
- `git -C upstream describe --tags --exact-match HEAD`
  - Result: `@better-auth/api-key@1.6.9`; the upstream tree is present and was compared from `upstream/packages/scim`.
- SCIM implementation shape:
  - At audit time, `packages/better_auth-scim/lib/better_auth/scim/routes.rb` was the largest runtime file at 433 lines.
  - Upstream equivalent behavior is split across `upstream/packages/scim/src/routes.ts`, `middlewares.ts`, `scim-tokens.ts`, `scim-filters.ts`, `patch-operations.ts`, `mappings.ts`, `scim-resources.ts`, and `user-schemas.ts`.

## Execution Evidence

- `cd packages/better_auth-scim && rbenv exec bundle exec rake test`
  - Result after implementation: `43 runs, 349 assertions, 0 failures, 0 errors, 0 skips`.
- `cd packages/better_auth-scim && rbenv exec bundle exec standardrb`
  - Result after implementation: passed with no output.
- Post-refactor SCIM runtime file sizes:
  - `routes.rb`: 297 lines.
  - `provider_management.rb`: 99 lines.
  - `validation.rb`: 51 lines.
- Continued execution evidence:
  - Added SQL schema coverage for `scimProvider.providerId` and `scimProvider.scimToken` unique constraints across PostgreSQL, SQLite, MySQL, and MSSQL generated DDL.
  - Expanded feature docs and user-facing docs for unsupported SCIM filters.

## Parity Summary

- Ruby covers the upstream SCIM v2 protocol surface: token generation, provider management, user CRUD, metadata endpoints, filter parsing, patch operations, hidden OpenAPI metadata, and client/plugin metadata.
- Ruby tests intentionally cover upstream cases from `scim.test.ts`, `scim-users.test.ts`, `scim-patch.test.ts`, and `scim.management.test.ts`.
- Organization role handling, provider ownership, default SCIM providers, token envelope format, and `store_scim_token` modes are closely aligned with upstream.
- Ruby intentionally uses snake_case options and `auth.api` method names while preserving upstream JSON and HTTP wire shapes.
- Ruby intentionally canonicalizes selected email/userName values to lowercase. This differs from upstream in account identity computation, where upstream `getAccountId(userName, externalId)` preserves `userName` if `externalId` is absent.

## High-Priority Findings

### P1: Provider identity can become ambiguous in adapters that do not enforce uniqueness

**Evidence:**

- SCIM schema declares `scimProvider.providerId` as unique in Ruby and upstream.
  - Ruby: `packages/better_auth-scim/lib/better_auth/plugins/scim.rb`
  - Upstream: `upstream/packages/scim/src/index.ts`
- Token generation looks up an existing provider by `{providerId, organizationId}` when `organizationId` is present.
  - Ruby: `packages/better_auth-scim/lib/better_auth/scim/routes.rb`
  - Upstream: `upstream/packages/scim/src/routes.ts`
- Provider management endpoints later look up and delete by `providerId` alone.
  - Ruby: `scim_provider_by_provider_id!` and `delete_scim_provider_connection`.
- The Ruby memory adapter does not enforce schema `unique: true`; a local probe created two `scimProvider` rows with the same `providerId` across different organizations. A user from the second organization then received `403` when trying to fetch their own provider because lookup returned the first row.

**Impact:** No public API shape change, but current in-memory behavior can produce ambiguous provider ownership and management. SQL schemas should reject duplicates, but the endpoint should not rely on database uniqueness for authorization correctness.

**Status:** Implemented. Token generation now checks existing providers by global `providerId` before create, matching the schema-level uniqueness expectation even when an adapter does not enforce uniqueness.

**Follow-up task:**

- [x] Modify `packages/better_auth-scim/lib/better_auth/scim/routes.rb` so `scim_generate_token_endpoint` checks existing providers by `providerId` alone before create.
- [x] If an existing provider has the same `providerId`, call `scim_assert_provider_access!` against that row before any delete or replacement.
- [x] Preserve upstream-style global `providerId` semantics: a user outside the owning organization must get `403`; a user with access may rotate the provider token.
- [x] Add a regression test to `packages/better_auth-scim/test/better_auth/scim/scim_management_test.rb` that creates one org-scoped provider and verifies another org owner cannot create the same `providerId` under a different org.
- [x] Run `cd packages/better_auth-scim && rbenv exec bundle exec ruby -Itest test/better_auth/scim/scim_management_test.rb`.
- [x] Run `cd packages/better_auth-scim && rbenv exec bundle exec rake test`.

### P2: SCIM account identity canonicalization is a Ruby-specific behavior that needs a locked decision

**Evidence:**

- Ruby computes account identity as `external_id || user_name.downcase`.
  - `packages/better_auth-scim/lib/better_auth/scim/mappings.rb`
- Upstream computes account identity as `externalId ?? userName`.
  - `upstream/packages/scim/src/mappings.ts`
- Ruby tests already document lowercase behavior for mixed-case user names and primary emails.
  - `packages/better_auth-scim/test/better_auth/scim/scim_test.rb`

**Impact:** Affects persisted `account.accountId` for SCIM-created users without `externalId`. HTTP response values are already canonicalized to lowercase email/userName in Ruby. This is probably acceptable for Ruby email canonicalization, but it is a meaningful upstream difference.

**Status:** Implemented as documentation. Ruby keeps lowercase canonicalization to preserve current behavior, and the difference from upstream is now documented.

**Follow-up task:**

- [x] Decide whether Ruby should continue lowercasing fallback SCIM `accountId`.
- [x] If keeping Ruby behavior, update `.docs/features/scim.md` and `docs/content/docs/plugins/scim.mdx` to explicitly document the canonicalization difference from upstream.
- [x] If aligning with upstream, change `scim_account_id` in `packages/better_auth-scim/lib/better_auth/scim/mappings.rb` to preserve `user_name` case when `external_id` is absent, then update affected tests. Not chosen; existing Ruby behavior was preserved.
- [x] Run `cd packages/better_auth-scim && rbenv exec bundle exec ruby -Itest test/better_auth/scim/scim_test.rb`. Covered by full package test run.
- [x] Run `cd packages/better_auth-scim && rbenv exec bundle exec rake test`.

### P2: User and account updates are not atomic for PATCH

**Evidence:**

- `scim_patch_user_endpoint` updates user and account separately after building patches.
  - `packages/better_auth-scim/lib/better_auth/scim/routes.rb`
- `scim_update_user_endpoint` wraps user/account updates in `ctx.context.adapter.transaction`.
- Upstream uses parallel updates for PATCH, so this is not a parity defect; it is a Ruby reliability improvement opportunity.

**Impact:** No public API shape change. If an adapter raises between the user update and account update, Ruby can persist a partial SCIM PATCH.

**Status:** Implemented. PATCH user/account writes now run inside `ctx.context.adapter.transaction`.

**Follow-up task:**

- [x] Wrap SCIM PATCH user/account writes in `ctx.context.adapter.transaction` in `packages/better_auth-scim/lib/better_auth/scim/routes.rb`.
- [x] Preserve the current `204` response and `No valid fields to update` behavior.
- [x] Add a regression test only if it can use a real adapter behavior; avoid mocks unless no real failure path is practical. Existing SCIM patch behavior tests were used because a real adapter failure path was not practical without mock-style instrumentation.
- [x] Run `cd packages/better_auth-scim && rbenv exec bundle exec ruby -Itest test/better_auth/scim/scim_patch_test.rb`.
- [x] Run `cd packages/better_auth-scim && rbenv exec bundle exec rake test`.

## Medium-Priority Findings

### P3: `routes.rb` is carrying too many responsibilities

**Evidence:** `packages/better_auth-scim/lib/better_auth/scim/routes.rb` contains endpoint definitions, provider authorization helpers, role parsing, validation, provider lookup, SCIM user lookup, and organization membership creation.

**Impact:** No runtime defect observed. The risk is future edits becoming harder to review, especially security-sensitive provider access logic.

**Status:** Implemented. Provider management helpers and request validation helpers were extracted from `routes.rb`.

**Follow-up task:**

- [x] Extract provider management helpers from `routes.rb` into `packages/better_auth-scim/lib/better_auth/scim/provider_management.rb`.
- [x] Extract body validation helpers from `routes.rb` into `packages/better_auth-scim/lib/better_auth/scim/validation.rb`.
- [x] Add `require_relative` entries in `packages/better_auth-scim/lib/better_auth/scim.rb` and `packages/better_auth-scim/lib/better_auth/plugins/scim.rb`.
- [x] Do not change endpoint names, routes, JSON shapes, or test expectations.
- [x] Run `cd packages/better_auth-scim && rbenv exec bundle exec rake test`.
- [x] Run `cd packages/better_auth-scim && rbenv exec bundle exec standardrb`.

### P3: Token comparison is mostly upstream-aligned but can be hardened in Ruby

**Evidence:**

- Default static providers use `BetterAuth::Crypto.constant_time_compare`.
  - `packages/better_auth-scim/lib/better_auth/scim/middlewares.rb`
- Stored DB tokens use plain string equality after optional hash/encrypt transforms.
  - `packages/better_auth-scim/lib/better_auth/scim/scim_tokens.rb`
- Upstream also uses equality checks, so this is hardening rather than parity.

**Impact:** No API change. For plain or hashed stored tokens, Ruby can make comparisons less timing-sensitive with a helper that handles unequal lengths safely.

**Status:** Implemented. Token verification now uses a shared length-safe constant-time comparison helper where string comparisons are made.

**Follow-up task:**

- [x] Add a private helper in `packages/better_auth-scim/lib/better_auth/scim/scim_tokens.rb` for safe string token comparison.
- [x] Use it for plain, hashed, custom hash, encrypted, and custom decrypt verification outputs where both sides are strings.
- [x] Keep invalid-token responses as `401` SCIM errors with detail `Invalid SCIM token`.
- [x] Run `cd packages/better_auth-scim && rbenv exec bundle exec ruby -Itest test/better_auth/scim/scim_management_test.rb`.
- [x] Run `cd packages/better_auth-scim && rbenv exec bundle exec rake test`.

## Intentional Ruby Adaptations To Preserve Unless Product Direction Changes

- [x] Ruby options are snake_case: `store_scim_token`, `default_scim`, `provider_ownership`, `required_role`, `before_scim_token_generated`, `after_scim_token_generated`.
- [x] SCIM protocol routes are hidden from generated OpenAPI output while management routes remain visible.
- [x] New SCIM-created users keep Ruby core defaults such as `emailVerified: false`.
- [x] Ruby canonicalizes selected email/userName response values to lowercase.
- [x] `before_scim_token_generated` currently runs after deleting an existing provider during rotation, matching upstream ordering. A hook failure invalidates the previous token; tests already lock this behavior.

## Lower-Priority Backlog

- [x] Add a docs note that `default_scim` entries take precedence over database providers with the same `providerId`, matching current tests and upstream behavior.
- [x] Add an operational docs snippet showing the SQL uniqueness invariant for `(providerId, accountId)` on accounts and global uniqueness for `scimProvider.providerId`.
- [x] Consider a follow-up audit against real SQL adapters, because memory tests cannot validate DB uniqueness, SQL constraint error mapping, or transaction rollback behavior. Completed with generated SQL schema coverage for SCIM provider uniqueness; broader real-adapter constraint error mapping remains outside this SCIM package pass.
- [x] Consider expanding docs for unsupported SCIM filters beyond `userName eq`, especially `externalId`, `ne`, `co`, `sw`, `ew`, and `pr`.

## Acceptance Criteria For Follow-Up Implementation

- [x] SCIM HTTP paths and JSON wire shapes remain upstream-compatible unless a task explicitly says otherwise.
- [x] `BetterAuth::Plugins.scim` option names remain backward-compatible.
- [x] Existing tests keep passing: `cd packages/better_auth-scim && rbenv exec bundle exec rake test`.
- [x] Formatting keeps passing: `cd packages/better_auth-scim && rbenv exec bundle exec standardrb`.
- [x] Any intentional upstream difference is documented in `.docs/features/scim.md` and, if user-facing, `docs/content/docs/plugins/scim.mdx`.
