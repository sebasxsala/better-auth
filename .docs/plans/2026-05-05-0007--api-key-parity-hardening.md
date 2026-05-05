# API Key Parity Hardening Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `better_auth-api-key` against the remaining upstream v1.6.9 parity gaps around list metadata migration, secondary-storage reference indexes, deferred background failures, and docs coverage.

**Architecture:** Keep runtime changes inside `packages/better_auth-api-key`. Preserve Ruby snake_case configuration, upstream camelCase wire fields, and the existing public API. Add focused Minitest coverage before implementation and update docs after behavior is green.

**Tech Stack:** Ruby, Minitest, StandardRB, Better Auth Ruby adapter/storage APIs, upstream `@better-auth/api-key@1.6.9` source under `upstream/`.

---

## Upstream Parity Audit

- [x] **Implemented baseline:** routes, response shapes, metadata/permissions decoding, organization-owned keys, multi-config, rate limits, usage limits, secondary storage, fallback-to-database, and API-key-backed user sessions are already covered by local tests.
- [x] **Intentionally unported:** Ruby does not expose a browser-only `apiKeyClient()` equivalent and does not port upstream endpoint OpenAPI metadata blocks.
- [x] **Targeted now:** list-route legacy metadata migration should batch/defer writes like upstream; secondary-storage reference indexes should accept raw arrays as well as JSON strings; deferred task failures should be logged; docs should include the cleanup route and current option set.

## Implementation Steps

- [x] **Step 1: Add failing tests**
  - Add an adapter test proving `list_for_reference` accepts a raw array reference index from custom storage.
  - Add a list-route test proving response metadata is parsed immediately while migration is scheduled through the configured background handler.
  - Add deferred failure logging tests for usage update, expired key deletion, and scheduled cleanup.

- [x] **Step 2: Implement metadata migration parity**
  - Add a batch helper that migrates only records whose metadata decodes to a hash but is not already canonical JSON.
  - Keep list responses synchronous by parsing metadata before returning.
  - Run migration via `run_in_background` when a background handler is configured; otherwise run inline.

- [x] **Step 3: Harden secondary-storage reference lists**
  - Update reference-list parsing to accept raw arrays and JSON strings.
  - Use the parser in both `safe_parse_id_list` and `list_for_reference`.
  - Wrap fallback `populate_reference` writes in `Adapter.batch` when the storage backend supports it.

- [x] **Step 4: Log deferred task failures**
  - Add one internal helper under `BetterAuth::APIKey::Utils` to run API-key background tasks with rescue-and-log behavior.
  - Use it for deferred usage updates, scheduled record deletion, and scheduled expired cleanup.

- [x] **Step 5: Update docs**
  - Add `/api-key/delete-all-expired-api-keys` to docs route tables.
  - Document `config_id`, `default_prefix`, `permissions`, and cleanup route usage where missing.
  - Preserve documentation of Ruby-specific intentional adaptations.

- [x] **Step 6: Verify**
  - Run `cd packages/better_auth-api-key && rbenv exec bundle exec rake test`.
  - Run `cd packages/better_auth-api-key && rbenv exec bundle exec standardrb`.

## Assumptions

- No gem version bump is needed because this is unreleased hardening work.
- Existing deleted `.docs/plans/*` files are user-owned worktree changes and should not be restored.
- Upstream source of truth remains the initialized `upstream/` submodule at `@better-auth/api-key@1.6.9`.
