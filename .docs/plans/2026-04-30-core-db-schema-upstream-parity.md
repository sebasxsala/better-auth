# Core DB Schema Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port Ruby-applicable upstream DB/schema/internal-adapter tests into `packages/better_auth`.

**Architecture:** Keep logical schema behavior in `Schema`, SQL rendering in `Schema::SQL`, adapter behavior in `Adapters::InternalAdapter`, and persistence behavior in adapter tests. Prefer real memory adapter behavior and database-backed tests when the existing suite already uses Docker services.

**Tech Stack:** Ruby 3.2+, Minitest, memory adapter, SQL adapters, Docker-backed database services where required.

---

## Audit Summary

Upstream files:

- `db/internal-adapter.test.ts` — 33 titles
- `db/db.test.ts` — 7 titles
- `db/get-migration-schema.test.ts` — 10 titles
- `db/secondary-storage.test.ts` — 4 titles
- `db/to-zod.test.ts` — 2 titles

Existing Ruby targets:

- `adapters/internal_adapter_test.rb` — 15 tests
- `schema_test.rb` — 9 tests
- `schema/sql_test.rb` — 5 tests
- Related adapter tests under `test/better_auth/adapters/*_test.rb`

Differences found:

- Ruby has solid core schema/internal adapter coverage, but upstream has more explicit cases for custom model names, custom field names, string coercion in where clauses, DB hook order, forced UUID preservation, verification cleanup, and adapter join behavior.
- Migration schema tests are TypeScript/Kysely-oriented, but Ruby should cover equivalent SQL/schema behavior for public schema/custom schema where applicable to existing SQL adapters.
- `to-zod` maps to Ruby input/output schema filtering; only the `returned: false` behavior is relevant.
- Secondary storage end-to-end behavior is partially covered through sessions/verifications, but upstream has explicit object/string return and revoked-session precedence cases.

## Tasks

### Task 1: Internal Adapter CRUD, Hooks, And Verification Lifecycle

**Files:**
- Modify: `packages/better_auth/test/better_auth/adapters/internal_adapter_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/adapters/internal_adapter.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/database_hooks.rb`

- [x] Translate create/find/update/delete cases for users, sessions, accounts, and verification records.
- [x] Add title-aligned tests for custom generate ID, forced UUID preservation, custom user/session/account field names, and string where-value coercion.
- [x] Add tests for before/after DB hooks, delete verification by value, delete verification by identifier, expired verification cleanup on find, and plugin hook identifiers.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/adapters/internal_adapter_test.rb`.

### Task 2: Schema Tables And Input/Output Filtering

**Files:**
- Modify: `packages/better_auth/test/better_auth/schema_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/schema.rb`

- [x] Translate upstream get-tables equivalents for base tables, plugin tables, custom model names, custom field names, additional fields, and table/field ordering.
- [x] Translate `to-zod` behavior as Ruby schema filtering: fields with `returned: false` remain valid input when client-side input is built and are excluded from output serialization.
- [x] Run schema tests.

### Task 3: SQL Migration Schema And Dialect Rendering

**Files:**
- Modify: `packages/better_auth/test/better_auth/schema/sql_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/schema/sql.rb`
- Modify as needed: SQL adapter wrappers if dialect metadata is missing.

- [x] Translate migration schema behavior to Ruby SQL output: custom table names, custom field names, JSON/array type handling, defaults, indexes, uniqueness, foreign keys, and plugin schema tables.
- [x] Document Kysely-only custom `search_path` and `CamelCasePlugin` inspection cases as Ruby exclusions unless an equivalent SQL adapter feature exists.
- [x] Run SQL schema tests.

### Task 4: Secondary Storage End-To-End

**Files:**
- Modify: `packages/better_auth/test/better_auth/routes/session_routes_test.rb`
- Modify: `packages/better_auth/test/better_auth/session_test.rb`
- Modify: `packages/better_auth/test/better_auth/adapters/internal_adapter_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/session.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/adapters/internal_adapter.rb`

- [x] Add explicit upstream cases for secondary storage returning strings and already-parsed objects.
- [x] Add revoked-session precedence tests where both database and secondary storage contain stale or deleted data.
- [x] Add verification secondary-storage tests for identifier overrides and hashed identifiers if not already title-aligned.
- [x] Run session and internal adapter tests.

### Task 5: Database Adapter Parity Check

**Files:**
- Modify existing adapter tests only where missing behavior is found.

- [x] Confirm memory adapter behavior covers upstream internal adapter semantics.
- [x] Confirm SQL/Postgres/MySQL/SQLite/MSSQL tests cover equivalent CRUD and route-backed persistence where applicable.
- [x] Document MongoDB external adapter coverage as outside `packages/better_auth` core if a test title belongs to `packages/better_auth-mongo-adapter`.
- [x] Run adapter tests that do not require unavailable services; run full suite with Docker services for final verification.

### Task 6: Final Verification

**Files:**
- Modify: `.docs/plans/2026-04-30-core-db-schema-upstream-parity.md`
- Modify: `.docs/plans/2026-04-29-core-upstream-test-parity.md`

- [x] Mark every DB/schema upstream title as `Ported`, `Covered by existing Ruby test`, or `Ruby exclusion documented`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec rake test`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec standardrb`.

## Upstream Title Status Matrix

### `db/db.test.ts`

| Upstream title | Status | Ruby coverage |
| --- | --- | --- |
| should work with custom model names | Ported | `schema_test.rb`, `schema/sql_test.rb` |
| db hooks | Ported | `internal_adapter_test.rb`, `user_routes_test.rb` |
| db hooks should preserve a forced UUID on postgres when generateId is uuid | Ported | `internal_adapter_test.rb` |
| should work with custom field names | Ported | `schema_test.rb`, `schema/sql_test.rb`, `session_routes_test.rb` |
| should coerce string where values to match field types | Ported | `internal_adapter_test.rb`, `sqlite_test.rb` |
| delete hooks | Ported | `user_routes_test.rb` |
| delete hooks abort | Ported | `user_routes_test.rb` |

### `db/internal-adapter.test.ts`

| Upstream title | Status | Ruby coverage |
| --- | --- | --- |
| should create oauth user with custom generate id | Ported | `internal_adapter_test.rb` |
| should find session with custom userId | Ported | `internal_adapter_test.rb` |
| should delete expired verification values on find | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should delete verification by value with hooks | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should delete verification by identifier with hooks | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should not call adapter.delete for missing verification record (prevents Prisma P2025) | Ported | `internal_adapter_test.rb` |
| should hash identifier when storeIdentifier is 'hashed' | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should use overrides for specific prefixes | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should fallback to plain lookup for old tokens | Ported | `internal_adapter_test.rb` |
| runs the after hook after adding user to db | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should calculate TTL correctly with Math.floor for secondary storage | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should create on secondary storage | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should delete on secondary storage | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should delete a single account | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should delete multiple accounts for a user | Covered by existing Ruby test | `internal_adapter_test.rb` |
| listSessions should skip missing sessions without blanking the list | Covered by existing Ruby test | `internal_adapter_test.rb` |
| listSessions should skip malformed session data (valid JSON but wrong structure) | Ported | `internal_adapter_test.rb` |
| listSessions should skip corrupt/unparsable sessions without blanking the list | Covered by existing Ruby test | `internal_adapter_test.rb` |
| listSessions should return empty array when all sessions are missing/corrupt | Covered by existing Ruby test | `internal_adapter_test.rb` |
| findSessions should skip corrupt sessions without blanking the list | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should update session and active-sessions list in secondary storage | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should deduplicate sessions when active-sessions list contains duplicates | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should store verification in secondary storage by default | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should find verification from secondary storage | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should NOT store in database when secondary-only mode | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should delete verification from secondary storage | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should store in both when storeInDatabase is true | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should fallback to database when not in secondary storage | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should set correct TTL based on expiresAt | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should return Date objects from findVerificationValue when storage returns pre-parsed objects | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should correctly detect expired verification when storage returns pre-parsed objects | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should return Date objects for all date fields across multiple reads | Covered by existing Ruby test | `internal_adapter_test.rb` |
| should preserve non-date string fields when reviving dates | Covered by existing Ruby test | `internal_adapter_test.rb` |

### `db/secondary-storage.test.ts`

| Upstream title | Status | Ruby coverage |
| --- | --- | --- |
| should work end-to-end with string return | Covered by existing Ruby test | `session_routes_test.rb` |
| should work end-to-end with object return | Covered by existing Ruby test | `session_routes_test.rb` |
| should not return a revoked session when it is deleted from both storages | Covered by existing Ruby test | `session_routes_test.rb` |
| should not return a revoked session even if it exists in database | Covered by existing Ruby test | `session_routes_test.rb` |

### `db/to-zod.test.ts`

| Upstream title | Status | Ruby coverage |
| --- | --- | --- |
| should include fields with returned: false in input schema (isClientSide: true) | Ported | `schema_test.rb` |
| should exclude fields with returned: false from output schema (isClientSide: false) | Ported | `schema_test.rb` |

### `db/get-migration-schema.test.ts`

| Upstream title | Status | Ruby coverage |
| --- | --- | --- |
| should detect custom schema from search_path | Ruby exclusion documented | Kysely/Postgres `search_path` inspection has no equivalent in current Ruby SQL renderer. |
| should detect custom schema with CamelCasePlugin enabled | Ruby exclusion documented | Kysely `CamelCasePlugin` inspection is TypeScript-specific. |
| should not be affected by tables in public schema when using custom schema | Ruby exclusion documented | Depends on Kysely/Postgres schema introspection, not Ruby SQL rendering. |
| should only inspect tables in public schema when using default connection | Ruby exclusion documented | Depends on Kysely/Postgres schema introspection, not Ruby SQL rendering. |
| should create tables in custom schema when running migrations | Ruby exclusion documented | Current Ruby core emits SQL statements; it does not manage Postgres `search_path` schemas. |
| should use uuid for id when `advanced.database.generateId` is set to 'uuid' | Ported | `internal_adapter_test.rb`; SQL DDL remains text because Ruby generates UUIDs before insert. |
| should use GENERATED ALWAYS AS IDENTITY instead of SERIAL when `advanced.database.generateId` is set to 'serial' | Ruby exclusion documented | Ruby `generate_id` currently supports callable and `uuid`; `serial` is not a public Ruby option. |
| should update default tables with plugin schema fields | Covered by existing Ruby test | `schema_test.rb`, `schema/sql_test.rb` |
| should generate valid PostgreSQL CREATE INDEX syntax for indexed columns added to existing tables | Ported | `schema/sql_test.rb` |
| should use CREATE INDEX when adding indexed columns to existing SQLite tables | Ported | `schema/sql_test.rb` |
