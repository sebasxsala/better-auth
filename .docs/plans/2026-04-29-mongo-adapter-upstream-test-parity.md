# Mongo Adapter Upstream Test Parity Implementation Plan

> **For agentic workers:** Execute with test-first discipline. Translate upstream tests before changing adapter behavior, then mark steps as complete as work progresses.

**Goal:** Bring `better_auth-mongo-adapter` test coverage into parity with applicable Better Auth `v1.6.9` Mongo adapter and adapter-factory suites.

**Architecture:** Add a dedicated Minitest parity suite with reusable helpers that run the upstream-normal adapter behaviors under ObjectId, joins, and UUID configurations. Keep Mongo-specific BSON/ObjectId tests explicit and skip only non-Ruby/non-server-client upstream coverage.

**Tech Stack:** Ruby, Minitest, `mongo`/`bson`, Better Auth Ruby adapter APIs.

---

## Scope

- [x] Translate applicable upstream Mongo adapter tests from:
  - `upstream/packages/mongo-adapter/src/mongodb-adapter.test.ts`
  - `upstream/e2e/adapter/test/mongo-adapter/adapter.mongo-db.test.ts`
  - `upstream/packages/test-utils/src/adapter/suites/basic.ts`
  - `upstream/packages/test-utils/src/adapter/suites/case-insensitive.ts`
  - `upstream/packages/test-utils/src/adapter/suites/auth-flow.ts`
  - `upstream/packages/test-utils/src/adapter/suites/transactions.ts`
  - `upstream/packages/test-utils/src/adapter/suites/uuid.ts`
- [x] Exclude non-applicable upstream coverage: browser/client/smoke tests, TypeScript type-only tests, Vitest adapter-factory helper tests, snapshots, and `numberIdTestSuite`.
- [x] Add translated tests before production code changes.
- [x] Record translated-test failures before implementation.

## Tasks

- [x] Add `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_upstream_parity_test.rb`.
- [x] Add reusable test helpers for deterministic users, sessions, accounts, plugin schemas, result sorting, and adapter setup.
- [x] Translate Mongo-specific BSON/ObjectId tests explicitly.
- [x] Translate the normal adapter suite in default ObjectId mode.
- [x] Reuse the normal adapter suite in joins-enabled mode, excluding only upstream's custom `generateId` override where upstream excludes it.
- [x] Reuse the normal adapter suite in UUID mode, excluding only upstream's custom `generateId` override where upstream excludes it.
- [x] Translate case-insensitive suite as explicit Ruby tests.
- [x] Translate auth-flow suite as real Better Auth API tests.
- [x] Translate transaction rollback suite, skipping unless `BETTER_AUTH_MONGODB_REPLICA_SET_URL` is configured.
- [x] Run `cd packages/better_auth-mongo-adapter && BUNDLE_GEMFILE=Gemfile bundle exec rake test` and record failures here.
- [x] Implement minimal adapter fixes until translated tests pass.
- [x] Run `cd packages/better_auth-mongo-adapter && BUNDLE_GEMFILE=Gemfile bundle exec rake test`.
- [x] Run `cd packages/better_auth-mongo-adapter && BUNDLE_GEMFILE=Gemfile bundle exec standardrb`.

## Failure Log

- [x] Initial translated-test run completed with Ruby 3.4.9 via `/Users/sebastiansala/.rbenv/shims/bundle`; system `/usr/bin/bundle` is unusable because it uses Ruby 2.6 and lacks Bundler 2.6.9.
- [x] Translation fixes needed before production changes: UUID regex omitted one UUID group, one test regenerated expected IDs by calling `user_data` twice, `numericField` tests need an additional field schema, and one string-operator fixture accidentally matched two `ends_with` rows.
- [x] Adapter behavior gap fixed: upstream shorthand limited joins such as `join: {session: {limit: 2}}` now preserve inferred join metadata and apply `limit`.
- [x] Final coverage check added missing important parity assertions for case-insensitive `ne`, `deleteMany` regex-literal operators, one-to-one select joins, mixed missing join shapes, null `eq/ne` AND/OR groups, and update with multiple AND conditions.
- [x] Removed the new upstream parity transaction skip by covering rollback with the fake transaction-capable Mongo client. Remaining skips are pre-existing real Mongo service / replica-set integration tests in `mongodb_test.rb`.

## Assumptions

- Repeated upstream suites should be represented by reusable Ruby helper contexts rather than copy-paste duplication.
- Server/database adapter behavior is in scope; browser/client/tooling coverage is out of scope for this Ruby package.
- Existing aggregate tests remain in place; parity tests add upstream-shaped behavior names and expectations.
