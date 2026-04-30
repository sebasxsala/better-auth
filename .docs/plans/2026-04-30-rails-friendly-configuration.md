# Rails-Friendly Configuration Implementation Plan

> **For agentic workers:** Track progress with these checkboxes. This plan implements the Rails configuration DSL while preserving existing hash assignment compatibility.

**Goal:** Make `better_auth-rails` configuration feel idiomatic in Rails by supporting nested block config and reducing default ActiveRecord boilerplate.

**Architecture:** Add a small Rails-only option builder that converts nested block assignments into plain option hashes. Keep core Better Auth untouched and feed the same hashes into `BetterAuth.auth`.

**Tech Stack:** Ruby, Rails adapter, RSpec, StandardRB, MDX docs.

---

### Task 1: Branch And Red Tests

- [x] Create branch `codex/rails-friendly-config`.
- [x] Add this implementation plan under `.docs/plans/`.
- [x] Add failing RSpec coverage for nested block config, hash compatibility, database adapter alias, and ActiveRecord adapter factory shorthand.
- [x] Run targeted RSpec and confirm the new tests fail for missing behavior.

### Task 2: Rails Configuration DSL

- [x] Add `BetterAuth::Rails::OptionBuilder`.
- [x] Update `BetterAuth::Rails::Configuration` to support block config for hash-like auth options.
- [x] Add `database_adapter = :active_record`.
- [x] Keep existing hash and array assignment behavior unchanged.
- [x] Make `BetterAuth::Rails::ActiveRecordAdapter.new` usable as a database factory when called without auth options.
- [x] Run targeted RSpec and confirm the behavior passes.

### Task 3: Rails Generator And Docs

- [x] Update the install initializer template to use block-style config and omit explicit ActiveRecord adapter boilerplate.
- [x] Update generator specs for the new template.
- [x] Update Rails-facing README and MDX docs that show old `config.database` lambdas or hash-heavy Rails config.
- [x] Run generator specs.

### Task 4: Verification

- [x] Run full `packages/better_auth-rails` RSpec suite.
- [x] Run StandardRB for `packages/better_auth-rails`.
- [x] Review git diff for scope and accidental unrelated changes.
