# Rails package hardening & Active Record / SQL parity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate serious correctness bugs in `better_auth-rails` (session isolation for controllers, LIKE wildcard safety, update/delete semantics, join aggregation parity with SQL adapter, configurable ID generation), expose `secrets` through Rails configuration, and document gaps—without opening uncontrollable scope (client proxies, empty env vars in deployment, or full multi-db sharding).

**Architecture:** Fix Rails controller/session integration by ensuring `BetterAuth::Context` uses per-request thread runtime before `Session.find_current` runs (same invariant as `BetterAuth::Router`). Implement adapter parity by aligning `ActiveRecordAdapter` with `BetterAuth::Adapters::Sql` for `update`, `delete`, `collection_join?`, and `aggregate_collection_joins`, extracting shared join logic into `packages/better_auth` so SQL and AR stay one behavioral source. Extend `BetterAuth::Rails::Configuration` with `:secrets` merged into `BetterAuth.auth`.

**Tech Stack:** Ruby 3.x, Rails (Railtie, Active Record), RSpec in `better_auth-rails`, Minitest in core `better_auth`, Rack.

---

## Explicit exclusions (why they are out of scope)

| Topic | Reason |
|--------|--------|
| Multi-database / `connected_to` / per-request shard routing | Requires a dedicated API (`abstract_parent`, role names, documentation). Not a bugfix-sized change. |
| Raw PK migration DDL across SQLite / Postgres / MySQL | Portable DDL is a migrations overhaul; high regression risk. Track separately if needed. |
| First-class DB `uuid` column types in generated migrations | Product/schema choice; apps can hand-edit migrations today. |
| Rotating installer default away from `secret_key_base` without a migration guide | Breaking for existing cookies/tokens; belongs to a “secrets migration” release, not this patch. |
| Automated audit of every auth negative path (wrong password, rate limits, …) | Entire-suite QA plan; this effort targets regressions for **changed code only**. |
| “Fix” empty `trusted_origins` when env unset | Deployment/configuration concern; document only (clients choose origins). |
| OptionBuilder rejecting unknown keys globally | Would break legitimate plugin/custom keys; document caution instead of runtime validation. |

---

## File map (what changes)

| File | Responsibility |
|------|----------------|
| `packages/better_auth-rails/lib/better_auth/rails/controller_helpers.rb` | Call `context.prepare_for_request!` before resolving session from cookies. |
| `packages/better_auth-rails/lib/better_auth/rails/configuration.rb` | Add `:secrets` to `AUTH_OPTION_NAMES` so merge hits core `SecretConfig`. |
| `packages/better_auth-rails/lib/better_auth/rails/active_record_adapter.rb` | LIKE escaping; `update`/`delete` aligned with `Sql`; `generated_id`; wire join aggregation; override `aggregate_collection_joins` as no-op. |
| `packages/better_auth/lib/better_auth/adapters/join_support.rb` (new) | Shared `normalized_join`, `normalize_join_config`, `reference_model_matches?`, `unique_join_field?`, `collection_join?` extracted from `sql.rb`. **NOT** `inferred_join_config` or `aggregate_collection_joins` (see Task 4 analysis). |
| `packages/better_auth/lib/better_auth/adapters/sql.rb` | Remove duplicated join methods; `include JoinSupport`. |
| `packages/better_auth/lib/better_auth/core.rb` (or adapter loader) | `require` new support files. |
| `packages/better_auth-rails/README.md` | Document `secrets`, `prepare_for_request!` expectations for custom Rack stacks, `trusted_origins` / env, OptionBuilder typos. |
| `packages/better_auth-rails/spec/better_auth/rails/controller_helpers_spec.rb` | Assert `prepare_for_request!` is called; no singleton `@current_session` leakage across sequential requests. |
| `packages/better_auth-rails/spec/better_auth/rails/active_record_adapter_spec.rb` + integration specs | LIKE, update/delete many rows, join aggregation, `generate_id: "uuid"`. |
| `packages/better_auth/test/...` | Minitest for `JoinSupport` and any `Sql` regression after extraction. |

---

## Known issues discovered during plan analysis (READ BEFORE EXECUTING)

### 1. Task 4 — `JoinSupport` extraction is more constrained than originally planned

**DO NOT move `inferred_join_config` or `aggregate_collection_joins` into `JoinSupport` without reading this:**

- `Sql#inferred_join_config` returns `{:relation, :unique, :from, :to}`. `ActiveRecordAdapter#inferred_join_config` returns `{:collection, :owner, :from, :to}`. These shapes are incompatible. `define_join_associations` in AR depends on `:collection` and `:owner`. If `JoinSupport` overrides AR's `inferred_join_config`, AR association definitions break.
- `Sql#aggregate_collection_joins` groups **flat SQL rows** by `id` and expects `record[join_model]` to be a **Hash** (from `normalize_joined_record`). In AR, `attach_joins` already produces an **Array** of normalized hashes for collection joins via ActiveRecord's eager loading. Feeding AR records into SQL's `aggregate_collection_joins` causes `NoMethodError: undefined method 'values' for Array`.

**Correct approach:** Extract only the join config *normalization* methods into `JoinSupport`. Keep `inferred_join_config` separate per adapter. In AR, override `aggregate_collection_joins` as a no-op (`records`) because ActiveRecord already deduplicates and aggregates collections. Make `collection_join?` handle both config shapes (see Task 4 Step 1).

### 2. Task 2 — SQL adapter has the SAME LIKE wildcard bug

`BetterAuth::Adapters::Sql#build_where` also interpolates `%#{value}%` without escaping. The plan originally only fixed AR. For hardening parity, add a private `escape_like` helper to `Sql` as well, or document it as a tracked gap. Recommended: fix both in this plan since the change is small.

### 3. Task 5 — `generated_id` default mismatch between adapters

Current SQL adapter uses `SecureRandom.hex(16)`. Current AR adapter uses `SecureRandom.urlsafe_base64(16)`. The original plan said "Match Sql#generated_id" but kept `urlsafe_base64(16)` in AR, which is inconsistent. The updated plan aligns both to `SecureRandom.hex(16)` for parity. If upstream fidelity matters more, both should change to `SecureRandom.alphanumeric(32)` later.

### 4. Task 1 — Double-request spec with real `Session.find_current` is over-complex

Setting up a real signed-in session (DB records, valid signed cookies, token lookup) in a controller spec is unnecessarily complex and brittle. The simpler, equally valid test is: assert that `prepare_for_request!` is invoked on the context with the request object, and that the context runtime is cleared between calls.

---

### Task 1: Session isolation in controller helpers (TDD)

**Files:**

- Modify: `packages/better_auth-rails/lib/better_auth/rails/controller_helpers.rb`
- Test: `packages/better_auth-rails/spec/better_auth/rails/controller_helpers_spec.rb`

- [x] **Step 1: Write a failing spec that proves the bug**

Add an example that asserts `prepare_for_request!` is called on `BetterAuth::Rails.auth.context` before session resolution. Use a spy/expectation on the context. Then add a second example proving that two sequential calls on the same thread with different requests clear the runtime session slot (i.e., `context.current_session` is nil after the second `prepare_for_request!`).

```ruby
it "prepares the auth context before resolving session" do
  request = instance_double(
    "Request",
    env: {},
    path: "/posts",
    request_method: "GET",
    query_parameters: {},
    get_header: "better-auth.session_token=signed-token"
  )
  controller = BetterAuthRailsHelperController.new(request)

  BetterAuth::Rails.configure do |config|
    config.secret = "test-secret-that-is-long-enough-for-validation"
    config.database = :memory
  end
  allow(BetterAuth::Session).to receive(:find_current).and_return({user: {"id" => "user-1"}})

  expect(BetterAuth::Rails.auth.context).to receive(:prepare_for_request!).with(request)

  controller.current_user
end

it "does not leak session state across sequential requests on the same thread" do
  BetterAuth::Rails.configure do |config|
    config.secret = "test-secret-that-is-long-enough-for-validation"
    config.database = :memory
  end

  ctx = BetterAuth::Rails.auth.context
  request_a = instance_double("Request", get_header: nil)
  request_b = instance_double("Request", get_header: nil)

  ctx.prepare_for_request!(request_a)
  ctx.set_current_session({id: "session-a"})

  ctx.prepare_for_request!(request_b)

  expect(ctx.current_session).to be_nil
end
```

Run:

```bash
cd packages/better_auth-rails && bundle exec rspec spec/better_auth/rails/controller_helpers_spec.rb --example "prepares"
```

Expected: **FAIL** (first example fails because `prepare_for_request!` is not called today; second example should pass because `prepare_for_request!` does clear runtime, but the first example proves the missing invocation).

- [x] **Step 2: Implement the fix**

At the start of `resolve_better_auth_session`, ensure request-scoped runtime exists and session slots are cleared:

```ruby
def resolve_better_auth_session
  ctx = BetterAuth::Rails.auth.context
  ctx.prepare_for_request!(request) if ctx.respond_to?(:prepare_for_request!)
  context = BetterAuth::Endpoint::Context.new(
    path: request.path,
    method: request.request_method,
    query: request.query_parameters,
    body: {},
    params: {},
    headers: {"cookie" => request.get_header("HTTP_COOKIE")},
    context: ctx,
    request: request
  )
  BetterAuth::Session.find_current(context, disable_refresh: true)
end
```

Run the same `rspec` command. Expected: **PASS**.

- [ ] **Step 3: Commit**

```bash
git add packages/better_auth-rails/lib/better_auth/rails/controller_helpers.rb packages/better_auth-rails/spec/better_auth/rails/controller_helpers_spec.rb
git commit -m "fix(rails): prepare auth context per controller request"
```

---

### Task 2: Escape LIKE patterns in ActiveRecordAdapter

**Files:**

- Modify: `packages/better_auth-rails/lib/better_auth/rails/active_record_adapter.rb` (`apply_operator` for `contains`, `starts_with`, `ends_with`)
- Optional modify: `packages/better_auth/lib/better_auth/adapters/sql.rb` (`build_where` for `contains`, `starts_with`, `ends_with`) — **same bug exists in SQL adapter**
- Test: `packages/better_auth-rails/spec/better_auth/rails/postgres_integration_spec.rb` (or unit spec with SQLite/memory fake)

- [x] **Step 1: Failing test**

Insert (via adapter `find_many` or low-level query) a row whose email literal contains `%` or `_`. Search `contains` with a user value meant to be literal (e.g. store `"a%b@x.test"` and query contains `"a%"`). Without escaping, extra rows match incorrectly **or** intended row misses depending on data.

Expected before fix: assertion fails on intended uniqueness semantics.

- [x] **Step 2: Implementation**

Add a private helper:

```ruby
def escape_like(value)
  string = value.to_s
  return string unless defined?(::ActiveRecord::Sanitization)

  ::ActiveRecord::Sanitization.sanitize_sql_like(string)
end
```

Use:

```ruby
when "contains" then scope.where("#{column} LIKE ? ESCAPE ?", "%#{escape_like(value)}%", "\\")
when "starts_with" then scope.where("#{column} LIKE ? ESCAPE ?", "#{escape_like(value)}%", "\\")
when "ends_with" then scope.where("#{column} LIKE ? ESCAPE ?", "%#{escape_like(value)}", "\\")
```

If MySQL rejects `ESCAPE '\'` in some modes, run integration spec on MySQL and adjust (MySQL typically accepts `ESCAPE '\\'` for backslash—verify against CI matrix).

- [x] **Step 3: (Optional but recommended) Fix SQL adapter too**

Add the same escaping to `Sql#build_where` in the `contains`/`starts_with`/`ends_with` branch. A simple string-based escape is sufficient since SQL uses parameterized queries:

```ruby
when "contains", "starts_with", "ends_with"
  pattern = case operator
  when "starts_with" then "#{escape_like(value)}%"
  when "ends_with" then "%#{escape_like(value)}"
  else "%#{escape_like(value)}%"
  end
  params << pattern
  "#{column} LIKE #{placeholder(params.length)}"
```

With a private helper:

```ruby
def escape_like(value)
  value.to_s.gsub("\\", "\\\\\\\\").gsub("%", "\\%").gsub("_", "\\_")
end
```

*(Use 4 backslashes in replacement because Ruby string `\\\\` → SQL string `\\` → regex replacement `\`, which is the literal backslash needed before `%`/`_` in LIKE.)*

Actually, simpler and safer:

```ruby
def escape_like(value)
  value.to_s.gsub("\\", "\\\\\\\\\\\\\\\\").gsub("%", "\\%").gsub("_", "\\_")
end
```

No—just use a straightforward implementation:

```ruby
def escape_like(value)
  string = value.to_s
  string = string.gsub("\\", "\\\\\\\\")
  string.gsub("%", "\\%").gsub("_", "\\_")
end
```

Wait, in Ruby replacement string for `gsub`, `\\\\` produces a single backslash. To emit a backslash before `%` in the result, the replacement string needs `\\%`. In a Ruby double-quoted string, `\\%` is `\%`. So:

```ruby
def escape_like(value)
  value.to_s.gsub("\\", "\\\\\\\\").gsub("%", "\\%").gsub("_", "\\_")
end
```

Ruby `\\\\\\\\` in replacement → result contains `\\` → two backslashes. But we want one backslash before each `%`/`_`. So:

```ruby
def escape_like(value)
  value.to_s.gsub("\\", "\\\\\\\\").gsub("%", "\\%").gsub("_", "\\_")
end
```

In replacement string `\\%`: Ruby interprets `\\` as two backslashes? No, in replacement strings for `gsub`, backslash escaping is different. Let's just use a block:

```ruby
def escape_like(value)
  value.to_s.gsub(/[\\%_]/) { |match| "\\#{match}" }
end
```

In the block, `"\\#{match}"` is a Ruby string where `\\` is one backslash character. So for `%`, it returns `"\%"` (backslash + percent). This is correct.

- [x] **Step 4: Run targeted specs**

```bash
cd packages/better_auth-rails && bundle exec rspec spec/better_auth/rails/postgres_integration_spec.rb spec/better_auth/rails/mysql_integration_spec.rb
cd packages/better_auth && bundle exec rake test
```

- [ ] **Step 5: Commit**

```bash
git commit -m "fix(rails): escape LIKE wildcards in ActiveRecordAdapter"
```

If SQL adapter was also fixed:

```bash
git commit -m "fix(core): escape LIKE wildcards in SQL adapter"
```

---

### Task 3: Align `update` and `delete` with SQL adapter semantics

**Files:**

- Modify: `packages/better_auth-rails/lib/better_auth/rails/active_record_adapter.rb`
- Reference: `packages/better_auth/lib/better_auth/adapters/sql.rb` (`update` lines 60–72, `delete` 95–97)

- [x] **Step 1: Failing integration test**

In `postgres_integration_spec.rb`, create **two** rows matching the same non-id predicate (e.g. same `userId` on a plugin table if schema allows, or duplicate logical field test row). Call adapter `update` with that `where` and assert **both** rows updated (reload both ids). Call adapter `delete` with predicate matching two rows; assert **zero** rows remain.

Expected before fix: only one row affected.

- [x] **Step 2: Implement**

Mirror `Sql#update`:

```ruby
def update(model:, where:, update:)
  model = model.to_s
  existing = find_one(model: model, where: where, select: ["id"])
  return nil unless existing

  update_many(model: model, where: where, update: update)
  find_one(model: model, where: [{field: "id", value: existing.fetch("id")}])
end
```

For PostgreSQL, optionally optimize later with `RETURNING`—not required for correctness here.

```ruby
def delete(model:, where:)
  delete_many(model: model, where: where)
  nil
end
```

Ensure `update_many` without returning uses `relation.update_all` for the non-returning path (already present).

- [x] **Step 3: Run specs**

```bash
cd packages/better_auth-rails && bundle exec rspec spec/better_auth/rails/postgres_integration_spec.rb spec/better_auth/rails/active_record_adapter_spec.rb
```

- [ ] **Step 4: Commit**

```bash
git commit -m "fix(rails): multi-row update/delete parity with SQL adapter"
```

---

### Task 4: Shared join aggregation (`JoinSupport`) in core + AR wiring

**Files:**

- Create: `packages/better_auth/lib/better_auth/adapters/join_support.rb`
- Modify: `packages/better_auth/lib/better_auth/adapters/sql.rb` (remove duplicate private methods now in module)
- Modify: `packages/better_auth-rails/lib/better_auth/rails/active_record_adapter.rb`
- Modify: `packages/better_auth/lib/better_auth/core.rb` (or wherever adapters are required) to `require` `join_support`
- Test: `packages/better_auth/test/better_auth/adapters/sql_test.rb` (or add `join_support_test.rb`) + rails integration join case

**CRITICAL:** Read "Known issues discovered during plan analysis" → Item 1 before implementing.

- [x] **Step 1: Extract sharable join methods into `JoinSupport`**

From `sql.rb`, move these methods into `module BetterAuth::Adapters::JoinSupport` as instance methods:

- `normalized_join`
- `normalize_join_config`
- `reference_model_matches?`
- `unique_join_field?`
- `collection_join?` — **must be updated** to handle both SQL and AR config shapes (see below)

**DO NOT move `inferred_join_config`**, `aggregate_collection_joins`, or `normalize_joined_record` into the module. Each adapter keeps its own `inferred_join_config` because return shapes differ (`:relation`/`:unique` vs `:collection`/`:owner`).

Update `collection_join?` to be shape-agnostic:

```ruby
def collection_join?(model, join)
  normalized_join(model, join).any? do |_join_model, config|
    if config.key?(:relation)
      config[:relation] != "one-to-one" && config[:unique] != true
    elsif config.key?(:collection)
      config[:collection] == true
    else
      false
    end
  end
end
```

Include the module in `BetterAuth::Adapters::SQL` **after** confirming method resolution still finds `schema_for`, `storage_field`, `table_for`, `fetch_key`, `storage_key` on the host class.

- [x] **Step 2: Include in ActiveRecordAdapter**

```ruby
module BetterAuth
  module Rails
    class ActiveRecordAdapter < BetterAuth::Adapters::Base
      include BetterAuth::Adapters::JoinSupport
```

**Override `aggregate_collection_joins` in AR** because ActiveRecord's eager loading already aggregates collection joins into arrays. SQL's `aggregate_collection_joins` expects flat rows and would crash on AR records (joined data is already an Array from `attach_joins`).

```ruby
def aggregate_collection_joins(_model, records, _join)
  records
end
```

Update `find_many` to call:

```ruby
collection_join?(model, join) ? aggregate_collection_joins(model, records, join) : records
```

(signature must match Sql).

Also update AR's `inferred_join_config` to additionally emit `:relation` and `:unique` keys so `collection_join?` works correctly:

```ruby
def inferred_join_config(model, join_model)
  # ... existing forward join logic ...
  unless foreign_keys.empty?
    # ...
    unique = attributes[:unique] == true
    return {
      from: reference.fetch(:field).to_s,
      to: foreign_key,
      collection: !unique,
      owner: :base,
      relation: unique ? "one-to-one" : "one-to-many",
      unique: unique
    }
  end

  # ... existing backward join logic ...
  {
    from: foreign_key,
    to: reference.fetch(:field).to_s,
    collection: false,
    owner: :join,
    relation: "one-to-one",
    unique: true
  }
end
```

Remove the stub `collection_join?` / `aggregate_collection_joins` that hard-code user/account (lines 337–343 of current file).

- [x] **Step 3: Core Minitest**

Run:

```bash
cd packages/better_auth && bundle exec rake test
```

Fix load-order / private method visibility issues.

- [x] **Step 4: Rails integration**

Extend postgres join test to assert grouped collection shape matches Sql adapter on the same dataset (existing spec partially covers joins—tighten assertions).

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(core): extract JoinSupport for SQL and ActiveRecord parity"
```

---

### Task 5: `generated_id` parity on ActiveRecordAdapter

**Files:**

- Modify: `packages/better_auth-rails/lib/better_auth/rails/active_record_adapter.rb`
- Optional: `packages/better_auth/lib/better_auth/adapters/sql.rb` — align default to `hex(16)` if desired

- [x] **Step 1: Spec**

With `options.advanced[:database][:generate_id] = "uuid"`, create row without id; assert UUID format. With `generate_id: -> { "fixed" }`, assert `"fixed"`.

- [x] **Step 2: Implementation**

Match `Sql#generated_id` **exactly** (including the same default):

```ruby
def generated_id
  generator = options.advanced.dig(:database, :generate_id)
  return generator.call.to_s if generator.respond_to?(:call)
  return SecureRandom.uuid if generator.to_s == "uuid"

  SecureRandom.hex(16)
end
```

In `transform_input`, replace the unconditional `urlsafe_base64` line with:

```ruby
output["id"] = generated_id if action == "create" && !output.key?("id")
```

**Note:** This changes the default ID format in AR from `urlsafe_base64(16)` to `hex(16)` to match SQL adapter parity. If this is a breaking concern for existing Rails apps, consider extracting `generated_id` into a shared module later.

- [ ] **Step 3: Commit**

```bash
git commit -m "fix(rails): honor database.generate_id in ActiveRecordAdapter"
```

---

### Task 6: Expose `secrets` on `BetterAuth::Rails::Configuration`

**Files:**

- Modify: `packages/better_auth-rails/lib/better_auth/rails/configuration.rb`
- Test: `packages/better_auth-rails/spec/better_auth/rails_spec.rb`

- [x] **Step 1: Spec**

```ruby
BetterAuth::Rails.configure do |c|
  c.secret = "a" * 32
  c.secrets = [{version: 1, value: "b"}, {version: 2, value: "c"}]
end
opts = BetterAuth::Rails.configuration.to_auth_options
expect(opts[:secrets]).to eq([{version: 1, value: "b"}, {version: 2, value: "c"}])
```

- [x] **Step 2: Add `:secrets` to `AUTH_OPTION_NAMES`**

Insert `:secrets` after `:secret` (keep alphabetical grouping if the file uses it—today it does not; place next to `secret`).

- [x] **Step 3: Run**

```bash
cd packages/better_auth-rails && bundle exec rspec spec/better_auth/rails_spec.rb
```

- [ ] **Step 4: Commit**

```bash
git commit -m "feat(rails): add secrets to Rails configuration merge"
```

---

### Task 7: README documentation (no scope creep)

**Files:**

- Modify: `packages/better_auth-rails/README.md`

- [x] **Step 1: Add sections**

1. **`secrets` / rotation:** Document `config.secrets = [...]` and `BETTER_AUTH_SECRETS`, and that they merge through `to_auth_options`.
2. **Trusted origins:** State that `ENV["BETTER_AUTH_URL"]` being unset yields an empty list and deployments should set origins explicitly for browser clients.
3. **OptionBuilder:** One paragraph—unknown keys are accepted; typos silently become option keys; validate against core docs.
4. **Controller integration:** Note that `ControllerHelpers` call `prepare_for_request!` (after Task 1); custom Rack middleware should do the same before reading session if bypassing `BetterAuth::Router`.

- [ ] **Step 2: Commit**

```bash
git commit -m "docs(rails): secrets, origins, OptionBuilder, context prepare"
```

---

## Self-review checklist

- [x] Every requirement above maps to Task 1–7.
- [x] No `TBD` / open-ended “add validation” steps.
- [x] `JoinSupport` does **not** contain `inferred_join_config` or `aggregate_collection_joins`.
- [x] AR adapter overrides `aggregate_collection_joins` as a no-op.
- [x] `collection_join?` handles both SQL (`:relation`/`:unique`) and AR (`:collection`) config shapes.
- [x] LIKE escaping is applied in AR; SQL adapter is either fixed or explicitly documented as a separate gap.
- [x] `generated_id` default in AR matches SQL (`hex(16)`).
- [x] `:secrets` spec uses valid `SecretConfig` shape (array of `{version, value}` hashes), not bare strings.

---

## Execution handoff

Plan saved to `.docs/plans/2026-05-03-1430--rails-hardening-sql-parity.md`.

**Two execution options:**

1. **Subagent-driven (recommended)** — REQUIRED SUB-SKILL: superpowers:subagent-driven-development — one fresh subagent per task, review between tasks.

2. **Inline execution** — REQUIRED SUB-SKILL: superpowers:executing-plans — batch tasks with checkpoints.

Which approach do you want?
