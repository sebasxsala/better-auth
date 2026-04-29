# Mongo Adapter Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Ruby MongoDB adapter into behavioral parity with upstream Better Auth Mongo adapter behavior for BSON IDs, Mongo-native operations, query semantics, joins, transactions, and docs.

**Architecture:** Keep the public Ruby constructor stable while moving storage/query work into Mongo-native operations. Use private helpers for BSON ID coercion, Mongo filters, aggregation pipelines, output normalization, and session-scoped transaction adapters.

**Tech Stack:** Ruby 3.4, Minitest, `mongo`/`bson`, Better Auth Ruby adapter contract, upstream Better Auth `packages/mongo-adapter`.

---

### Task 1: Upstream Context And Failing Parity Tests

**Files:**
- Modify: `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb`
- Verify: `upstream/packages/mongo-adapter/src/mongodb-adapter.ts`

- [x] **Step 1: Initialize upstream**

Run: `git submodule update --init upstream`

Expected: `upstream` checks out `f484269228b7eb8df0e2325e7d264bb8d7796311`.

- [x] **Step 2: Add failing tests**

Add tests for constructor smoke, BSON UUID storage/output, custom ID bypass, case-insensitive where modes, unsupported operators, invalid ID values, native update/delete counts, select, and generic join config.

- [x] **Step 3: Run tests to verify failures**

Run: `cd packages/better_auth-mongo-adapter && bundle exec ruby -Itest test/better_auth/adapters/mongodb_test.rb`

Expected: failures showing current ObjectId-only UUID handling, silent unsupported operators, missing case-insensitive mode, full-collection mutation paths, and non-generic joins.

### Task 2: BSON ID And Query Parity

**Files:**
- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`
- Test: `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb`

- [x] **Step 1: Implement BSON UUID helpers**

Use `BSON::Binary.from_uuid(value)` when `options.advanced.dig(:database, :generate_id) == "uuid"` and `BSON::Binary#to_uuid` on output.

- [x] **Step 2: Implement Mongo filter generation**

Translate `where` to Mongo predicates with escaped regexes, `mode: "insensitive"` support, `$and`/`$or` connector buckets, ID/reference coercion, and `MongoAdapterError` codes `INVALID_ID` and `UNSUPPORTED_OPERATOR`.

- [x] **Step 3: Run focused tests**

Run: `cd packages/better_auth-mongo-adapter && bundle exec ruby -Itest test/better_auth/adapters/mongodb_test.rb`

Expected: UUID/query/error tests pass or move to implementation-specific failures in Task 3.

### Task 3: Native Mongo Operations And Joins

**Files:**
- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`
- Test: `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb`

- [x] **Step 1: Replace materialized CRUD paths**

Use `aggregate`, `find_one_and_update`, `update_many`, `delete_one`, `delete_many`, and aggregation count with session options.

- [x] **Step 2: Build aggregation joins**

Support existing simple join callers and upstream-style join configs with `on.from`, `on.to`, `relation`, and `limit`; map logical `id` to `_id`, honor storage field names, and unwind one-to-one joins.

- [x] **Step 3: Run focused tests**

Run: `cd packages/better_auth-mongo-adapter && bundle exec ruby -Itest test/better_auth/adapters/mongodb_test.rb`

Expected: adapter tests pass.

### Task 4: Transaction Safety And Docs

**Files:**
- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`
- Modify: `docs/content/docs/adapters/mongo.mdx`

- [x] **Step 1: Use session-scoped transaction adapter**

Create a new adapter instance carrying the transaction session for the callback, instead of mutating `@session` on the shared adapter.

- [x] **Step 2: Update docs**

Document `better_auth-mongo-adapter`, `require "better_auth/mongo_adapter"`, lambda database setup, `transaction`, `use_plural`, ObjectId defaults, UUID storage, and the intentionally unported `debugLogs` option.

- [x] **Step 3: Run affected suites**

Run:

```bash
cd packages/better_auth-mongo-adapter && bundle exec rake test
cd ../better_auth && bundle exec ruby -Itest test/better_auth/adapters/mongodb_external_shim_test.rb
```

Expected: all affected tests pass; real Mongo route tests skip when no Mongo service is available.

### Task 5: Upstream Factory Suite Audit Gaps

**Files:**
- Modify: `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb`
- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`
- Verify: `upstream/packages/test-utils/src/adapter/suites/basic.ts`
- Verify: `upstream/packages/test-utils/src/adapter/suites/case-insensitive.ts`
- Verify: `upstream/packages/test-utils/src/adapter/suites/uuid.ts`
- Verify: `upstream/e2e/adapter/test/mongo-adapter/adapter.mongo-db.test.ts`

- [x] **Step 1: Add parity tests for remaining factory behavior**

Add tests for custom model/field names, additional/default fields, nullable references, date fields, comparison operators, sort/limit/offset ordering, on-update values, empty results, regex literal escaping, invalid `in` values, JSON fields, and select with joins.

- [x] **Step 2: Add schema-driven join tests**

Add tests for inferred forward/backward joins, one-to-one plugin joins, custom field names inside joins, join limits, one-to-one no-match `nil`, one-to-many no-match `[]`, and missing/ambiguous FK errors.

- [x] **Step 3: Add Mongo-specific real database coverage**

Add real Mongo tests for native update/delete/count operations, ObjectId FK preservation after update, auth flow parity, and transaction rollback when a replica-set-capable URL is provided.

- [x] **Step 4: Implement remaining parity gaps**

Port upstream adapter factory behavior for schema-driven model and field resolution, where value coercion, JSON stringify/parse, `in` array validation, schema-inferred joins, and joined-empty output defaults.

- [x] **Step 5: Run affected suites**

Run:

```bash
cd packages/better_auth-mongo-adapter && bundle exec rake test
cd packages/better_auth-mongo-adapter && bundle exec standardrb
cd packages/better_auth && bundle exec ruby -Itest test/better_auth/adapters/mongodb_external_shim_test.rb
```

Expected: all affected tests pass; real Mongo tests run when the service is available, and replica-set transaction tests skip explicitly unless configured.
