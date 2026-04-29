# Hanami Adapter Audit Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `test-driven-development` while implementing this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix focused Hanami adapter audit findings and preserve false-valued adapter predicates across Better Auth adapters.

**Architecture:** Keep framework-agnostic adapter contract fixes in each adapter package. Keep Hanami-specific route, generator, mounted Rack path, and migration fixes inside `packages/better_auth-hanami`.

**Tech Stack:** Ruby 3.4, Better Auth core, Hanami 2.3, Rack 3, Sequel/ROM::SQL, Active Record, MongoDB adapter shims, Minitest, RSpec, StandardRB.

---

## Tasks

- [x] Create and switch to `codex/hanami-adapter-audit-fixes` from `canary`.
- [x] Initialize `upstream/` at pinned commit `f484269228b7eb8df0e2325e7d264bb8d7796311`.
- [x] Add failing tests for Hanami routing require coverage, generator route insertion, script-name mounting, bigint migrations, and false predicates.
- [x] Make Hanami route examples/generator use `require "better_auth/hanami"` and ensure `better_auth` is inserted even when the include already exists.
- [x] Make `MountedApp` forward core paths under the configured auth mount path while ignoring unrelated Rack `SCRIPT_NAME` prefixes.
- [x] Render Hanami bigint number columns as `:Bignum`.
- [x] Replace truthy `fetch_key` helpers with key-preserving lookup helpers in core memory/SQL, Hanami Sequel, Rails Active Record, and MongoDB adapters.
- [x] Run the targeted test plan and Hanami StandardRB.

## Follow-Up Work

- OAuth/social, organization, and two-factor parity/security findings from the audit are intentionally out of scope for this branch and should be handled on separate branches.
