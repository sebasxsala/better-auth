# Mongo Adapter Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `better_auth-mongo-adapter` after parity review by improving production setup docs, index support, and test maintainability without changing the existing adapter contract.

**Architecture:** Keep upstream v1.6.9 behavior as the default source of truth. Add Mongo-specific production affordances only where Ruby needs them because Mongo has no schema migration layer. Keep behavior changes covered by package-level Minitest tests and optional real Mongo smoke tests.

**Tech Stack:** Ruby 3.4, `mongo` gem, Minitest, Better Auth schema metadata, upstream `packages/mongo-adapter`.

---

## Summary

Current state is healthy: `rbenv exec bundle exec rake test` passes in `packages/better_auth-mongo-adapter` with 63 runs, 235 assertions, 1 environment skip, and `standardrb` is clean.

Important findings:

- The Ruby adapter already covers more Mongo parity behavior than upstream's package-local unit tests, including joins, UUID/ObjectId mapping, typed where coercion, auth flows, and transaction behavior.
- The README's main setup example should use the lambda adapter form so Better Auth passes final options, plugins, and advanced database config into the adapter.
- Mongo has no migrations, so unique/index metadata is not enforced unless users manually create indexes. This is the biggest production hardening gap.
- The package has duplicate fake Mongo implementations; this increases test drift and makes transaction/session coverage weaker than it needs to be.
- Scalar `in`/`not_in` support is a Ruby cross-adapter adaptation. Keep it, but document it as intentional because upstream's factory layer is stricter than the custom Mongo adapter internals.

## Implementation Steps

- [x] Restore/create the plan file at `.docs/plans/2026-05-04-2206--mongo-adapter-hardening.md` with this content, using `.docs/plans/` per `AGENTS.md`.

- [x] Update `packages/better_auth-mongo-adapter/README.md` so the primary example uses `database: ->(options) { BetterAuth::Adapters::MongoDB.new(options, ...) }`, includes `transaction: false` for standalone/local Mongo, and explains when to enable transactions.

- [x] Update `docs/content/docs/adapters/mongo.mdx` to match the README transaction guidance and clarify that Mongo schema migration is not required, but indexes are still recommended for production.

- [x] Add `BetterAuth::Adapters::MongoDB#ensure_indexes!` as an explicit opt-in helper. It should inspect `Schema.auth_tables(options)`, create indexes for fields with `unique: true` or `index: true`, skip `_id`, use storage field names, and return a summary of indexes requested.

- [x] Add fake Mongo index support in `test/support/fake_mongo.rb` by recording `collection.indexes.create_one(keys, options)` calls.

- [x] Test `ensure_indexes!` with core schema and plugin schema: user email unique, session token unique, session/account `user_id` indexes, rate-limit key when enabled, and custom field/model names.

- [x] Consolidate Mongo fake test support by replacing the embedded fake classes in `mongodb_test.rb` with `require_relative "../../support/fake_mongo"` and adding any missing recorder methods to the shared support file.

- [x] Strengthen transaction harness coverage so fake sessions record session options for insert/update/delete/count paths and rollback staged updates/deletes in at least one focused test.

- [x] Add a parity note test or doc line for Ruby's scalar `in`/`not_in` behavior, explicitly treating it as a Ruby adapter-family adaptation rather than accidental upstream parity.

- [x] Update `packages/better_auth-mongo-adapter/CHANGELOG.md` under `Unreleased` with the index helper, docs correction, and fake harness consolidation.

## Test Plan

- [x] Run `rbenv exec bundle exec rake test` in `packages/better_auth-mongo-adapter`.
- [x] Run `rbenv exec bundle exec standardrb` in `packages/better_auth-mongo-adapter`.
- [ ] If local Mongo is available, run the existing real-service tests with `BETTER_AUTH_MONGODB_URL`.
- [ ] If a replica-set URL is available, run transaction rollback coverage with `BETTER_AUTH_MONGODB_REPLICA_SET_URL`.

## Execution Notes

- Implemented `ensure_indexes!` as an explicit setup helper; it returns the collection, logical field, Mongo key, and uniqueness for each requested index.
- Consolidated `mongodb_test.rb` onto `test/support/fake_mongo.rb` and extended the shared fake driver with index recording plus transaction-scoped insert/update/delete/count state.
- Verification on 2026-05-05: `rbenv exec bundle exec rake test` passed with 65 runs, 272 assertions, 1 environment-gated skip. `rbenv exec bundle exec standardrb` passed.

## Assumptions

- Use `.docs/plans/`, not `.docs/plan`, because the root `AGENTS.md` requires that directory.
- Do not bump gem versions; this is unreleased hardening unless a release is requested.
- Do not auto-create indexes in `initialize`; index creation should remain an explicit deploy/setup action.
- Do not port upstream `debugLogs`; Ruby core does not currently expose the same adapter debug logging contract.
