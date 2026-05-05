# Hanami Sequel Adapter Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `better_auth-hanami` Sequel persistence closer to upstream Better Auth adapter behavior for plugin JSON/array fields and schema-driven joins.

**Architecture:** Keep the Hanami adapter Rack/Hanami-specific, but reuse the same adapter behaviors already proven in the Ruby core SQL adapter where possible. The Sequel adapter should serialize JSON-like values before writes, parse them after reads when the database returns strings, escape `LIKE` patterns, and infer joins from `BetterAuth::Schema.auth_tables` instead of hard-coding only `session -> user`, `account -> user`, and `user -> account`.

**Tech Stack:** Ruby 3.2+, Better Auth Ruby core, Hanami 2.3, Sequel, ROM::SQL migrations, RSpec, StandardRB, upstream Better Auth v1.6.9 adapter test expectations.

---

## Analysis Summary

- [x] Read root `AGENTS.md`.
- [x] Checked package-level instructions; no `packages/better_auth-hanami/AGENTS.md` exists.
- [x] Reviewed Hanami package implementation under `packages/better_auth-hanami/lib/better_auth/hanami`.
- [x] Reviewed Hanami specs under `packages/better_auth-hanami/spec`.
- [x] Compared behavior against upstream v1.6.9 adapter tests in `upstream/packages/test-utils/src/adapter/suites/basic.ts` and `upstream/packages/test-utils/src/adapter/suites/joins.ts`.
- [x] Compared Ruby adapter behavior against `packages/better_auth/lib/better_auth/adapters/sql.rb` and `packages/better_auth/lib/better_auth/adapters/join_support.rb`.
- [x] Ran `rbenv exec bundle exec rspec` in `packages/better_auth-hanami`: 37 examples, 0 failures.
- [x] Ran `rbenv exec bundle exec standardrb` in `packages/better_auth-hanami`: passed.
- [x] Reproduced a missing behavior for plugin `json`, `string[]`, and `number[]` fields: `BetterAuth::Hanami::SequelAdapter#create` passes Ruby `Hash`/`Array` values directly to Sequel, which produced invalid SQLite SQL such as ``(`foo` = 'bar')`` and `('a', 'b')`.
- [x] Reproduced missing schema-driven join behavior: joining a plugin one-to-one table from `user` returns the base user without the joined record.

## Upstream And Local Evidence

Upstream v1.6.9 adapter coverage expects:

- `create - should support arrays` and `create - should support json` in `upstream/packages/test-utils/src/adapter/suites/basic.ts`.
- `findOne`/`findMany` joins for one-to-one plugin models, modified field names, and combined one-to-one plus one-to-many joins in `upstream/packages/test-utils/src/adapter/suites/basic.ts`.
- The joins suite reuses the normal adapter suite with `experimental.joins = true` in `upstream/packages/test-utils/src/adapter/suites/joins.ts`.

Local Ruby core already has reusable behavior to adapt:

- `packages/better_auth/lib/better_auth/adapters/sql.rb` serializes JSON-like values with `JSON.generate`, parses JSON-like strings on output, escapes `LIKE`, and supports generalized join inference through `JoinSupport`.
- `packages/better_auth/lib/better_auth/adapters/join_support.rb` normalizes explicit and inferred join configuration from schema references.

Hanami currently handles:

- Core signup/signin/get-session flow against Sequel.
- Basic route mounting through a real Hanami route set.
- Base and plugin migration rendering.
- Basic hard-coded joins for `session -> user`, `account -> user`, and `user -> account`.

Hanami currently does not handle well:

- JSON/array plugin persistence through `BetterAuth::Hanami::SequelAdapter`.
- General schema-driven joins for plugin relations or modified reference fields.
- Escaping `%`, `_`, and `\` in Sequel `LIKE` predicates; upstream tests assert pattern-like strings are literal, and local SQL adapter already handles this.

## Task 1: Add Failing Sequel Adapter Parity Specs

**Files:**
- Modify: `packages/better_auth-hanami/spec/better_auth/hanami/sequel_adapter_spec.rb`

- [x] Add an RSpec example named `persists and reads plugin json and array fields`.
- [x] Configure a plugin schema with `metadata: {type: "json"}`, `tags: {type: "string[]"}`, and `scores: {type: "number[]"}`.
- [x] Apply `BetterAuth::Hanami::Migration.render(config)` to an in-memory SQLite database using the existing `apply_migration` helper.
- [x] Create a `testModel` record through `BetterAuth::Hanami::SequelAdapter`.
- [x] Assert the returned and reloaded record preserve `{"foo" => "bar"}`, `["a", "b"]`, and `[1, 2]`.
- [x] Confirm the new example fails before implementation with the reproduced Sequel/SQLite error.

## Task 2: Add Failing Schema-Driven Join Specs

**Files:**
- Modify: `packages/better_auth-hanami/spec/better_auth/hanami/sequel_adapter_spec.rb`

- [x] Add an RSpec example named `joins plugin one-to-one models inferred from schema references`.
- [x] Configure a plugin table `oneToOneTable` with `oneToOne` referencing `user.id`, marked `unique: true`.
- [x] Create a user and one-to-one row through the Sequel adapter.
- [x] Assert `find_one(model: "user", join: {oneToOneTable: true})` includes `"oneToOneTable"` with the joined record.
- [x] Add a second assertion for `find_many(model: "user", join: {oneToOneTable: true, session: true})` so one-to-one joins and collection joins can coexist.
- [x] Confirm the new example fails before implementation because the current `attach_joins` ignores plugin join models.

## Task 3: Serialize JSON-Like Values And Escape LIKE

**Files:**
- Modify: `packages/better_auth-hanami/lib/better_auth/hanami/sequel_adapter.rb`

- [x] Add `require "json"` near the existing `require "time"`.
- [x] Update `coerce_value` so `json`, `string[]`, and `number[]` values are stored with `JSON.generate(value)` unless already a string.
- [x] Update `coerce_output_value` so JSON-like strings are parsed with `JSON.parse`, returning the original value if parsing fails.
- [x] Add `json_like?(attributes)` and `parse_json_value(value)` helpers matching the Ruby core SQL adapter behavior.
- [x] Add `coerce_where_value(value, attributes)` so boolean, number, date, and JSON-like where values are coerced consistently before predicate construction.
- [x] Use `coerce_where_value` in `where_expression` for equality, inequality, ordering, and `in`/`not_in` values.
- [x] Add `escape_like(value)` and use `Sequel.like(identifier, pattern, escape: "\\")` for `contains`, `starts_with`, and `ends_with`.

## Task 4: Replace Hard-Coded Joins With Schema-Driven Join Support

**Files:**
- Modify: `packages/better_auth-hanami/lib/better_auth/hanami/sequel_adapter.rb`

- [x] Include `BetterAuth::Adapters::JoinSupport` in `BetterAuth::Hanami::SequelAdapter`.
- [x] Add `schema_models`, `reference_model_matches?`, and `inferred_join_config` helpers if the mixin requires adapter-local implementations beyond `schema_for`, `storage_field`, and `table_for`.
- [x] Replace `attach_joins` hard-coded cases with logic based on `normalized_join(model, join)`.
- [x] For one-to-one joins, query the joined model with `{field: config.fetch(:to), value: record.fetch(config.fetch(:from))}` when the joined model references the base model.
- [x] For one-to-many joins, return arrays and honor `limit` when provided in the join config.
- [x] Preserve current behavior for `session -> user`, `account -> user`, and `user -> account`.
- [x] Ensure missing one-to-one joins return `nil` and missing collection joins return `[]`, matching upstream expectations.

**Implementation note:** `JoinSupport` already provides `reference_model_matches?`, and `schema_models` was not required for the Hanami separate-query join implementation. The adapter added its own `inferred_join_config` matching the core SQL adapter's schema inference.

## Task 5: Verify Hanami Package

**Files:**
- Verify only.

- [x] Run `rbenv exec bundle exec rspec` from `packages/better_auth-hanami`.
- [x] Run `rbenv exec bundle exec standardrb` from `packages/better_auth-hanami`.
- [x] If implementation changes shared adapter logic or extracts helpers into `packages/better_auth`, also run the affected core specs with `rbenv exec bundle exec rake test` from the repo root.

**Verification note:** Shared core adapter logic was not changed, so no root core test run was required. Hanami package verification passed with 40 RSpec examples and StandardRB.

## Notes For Implementation

- Do not bump `packages/better_auth-hanami/lib/better_auth/hanami/version.rb`; this is not a release task.
- Do not overwrite user-created Hanami relations, repos, providers, or migrations.
- Keep the upstream submodule at v1.6.9. It is already initialized at `f484269228b7eb8df0e2325e7d264bb8d7796311`.
- The current worktree already has unrelated deleted `.docs` files. Do not restore or remove them as part of this work.
