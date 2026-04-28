# Plugin Upstream Deltas Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` or `executing-plans` to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Bring Ruby `anonymous`, `api_key`, `bearer`, and `captcha` behavior back in line with current upstream.

**Architecture:** Keep upstream runtime behavior in the matching Ruby plugin package or core plugin file. Ruby keeps snake_case options while preserving upstream JSON field names and documents server-only/client-only adaptations.

**Tech Stack:** Ruby 3.2+, Rack, Minitest, StandardRB, upstream TypeScript reference under `upstream/`.

---

## Context

`.docs/plans/2026-04-25-better-auth-ruby-port.md` is referenced by repository instructions but is absent in this checkout. The active plugin parity tracking document is `.docs/plans/2026-04-27-plugin-parity-completion.md`.

Upstream `api-key` is now a separate package at `upstream/packages/api-key/src/**`; the Ruby port mirrors that with `packages/better_auth-api-key/` and keeps a core compatibility shim at `packages/better_auth/lib/better_auth/plugins/api_key.rb`.

## Tasks

- [x] Document the current upstream delta plan and package boundary.
- [x] Update API key docs to reference `upstream/packages/api-key/src/**`.
- [x] Implement API key `configId`, `referenceId`, `defaultPrefix`, multiple configurations, verify/list response contracts, organization-owned keys, prefix validation, callable default permissions, and upstream secondary-storage key names with legacy read fallback.
- [x] Harden bearer scheme parsing, signed token URL encoding/decoding, and expired Set-Cookie handling.
- [x] Harden captcha error codes, IP extraction through `BetterAuth::RequestIP`, provider payloads, route coverage, endpoint overrides, provider failures, and URL override tests.
- [x] Harden anonymous generated email validation and Set-Cookie name matching, plus schema/linking guard coverage.

## Verification

- [x] `cd packages/better_auth-api-key && rbenv exec bundle exec ruby -Itest test/better_auth/api_key_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/anonymous_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/bearer_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/captcha_test.rb`

## Follow-Up

- [ ] Run the full core and package CI after the unrelated worktree changes settle.
- [ ] Keep `.docs/features/upstream-parity-matrix.md`, `README.md`, and package README rows aligned when plugin packages are promoted or extracted.
