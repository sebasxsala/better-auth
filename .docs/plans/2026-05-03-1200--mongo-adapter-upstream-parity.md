# Mongo adapter upstream parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align `BetterAuth::Adapters::MongoDB` with upstream `@better-auth/mongo-adapter` + core adapter factory behavior for join limits, default `find_many` limits, `in`/`not_in` value shapes, and multi-clause `where` composition—without chasing environmental limits (replica sets) or features Ruby core does not support (`debugLogs`).

**Architecture:** Centralize a private `default_find_many_limit` reader on the Mongo adapter (mirroring `options.advanced.database.defaultFindManyLimit`, exposed in Ruby as `advanced[:database][:default_find_many_limit]`). Use it to cap one-to-many `$lookup` subpipelines and top-level `find_many` aggregation `$limit`. Replace the left-fold `mongo_filter` combinator with upstream’s connector-bucket model (`$and` list + `$or` list). Keep BSON/driver constraints unchanged.

**Tech Stack:** Ruby 3.x, `mongo` gem, Minitest, `packages/better_auth` Configuration (`advanced` hash).

---

## Plan review notes (added after analysis)

- **Why limits belong in the adapter:** Upstream’s core `adapterFactory.ts` normalizes joins (always injecting `limit`) and top-level `findMany` (always injecting `limit = unsafeLimit ?? defaultFindManyLimit ?? 100`) *before* reaching the Mongo adapter. Ruby core does not have this factory layer, so the Mongo adapter must perform the same normalization itself to achieve parity.
- **Join pipeline syntax change:** Because upstream’s factory always sets `limit` on one-to-many joins, the upstream Mongo adapter always uses `$lookup` + pipeline syntax for one-to-many relationships. After this plan, the Ruby adapter will do the same (previously it used simple `$lookup` for inferred one-to-many joins without an explicit limit).
- **AND/OR bucket semantics:** In MongoDB, a top-level filter like `{ $and: [A, C], $or: [B] }` is semantically equivalent to `A AND B AND C` because a single-element `$or` is equivalent to its inner expression and top-level keys are ANDed. The old left-fold produced nested structures like `{ $and: [ { $or: [A, B] }, C ] }` (`(A OR B) AND C`), which is **not** the same. One existing test relies on the old left-fold semantics and must be updated.

## Execution notes (2026-05-04)

- Compared against upstream `packages/core/src/db/adapter/factory.ts` and `packages/mongo-adapter/src/mongodb-adapter.ts` at the checked-out submodule version. Implemented the Ruby-specific normalization inside `BetterAuth::Adapters::MongoDB` because Ruby has no matching adapter factory layer for this package.
- Preserved upstream behavior for explicit `limit: 0`: it disables a positive `$limit` stage instead of falling back to the default.
- Updated fake Mongo filter matching so top-level `$and` and `$or` keys are evaluated together like MongoDB.
- Verification: `rbenv exec bundle exec rake test` in `packages/better_auth-mongo-adapter` passed with 63 runs, 215 assertions, 4 skips.

---

## File map

| File | Role |
|------|------|
| `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb` | Implement limits, `mongo_filter`, `in`/`not_in` scalar handling |
| `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb` | Fake Mongo regression tests |
| `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_upstream_parity_test.rb` | Broader parity scenarios |
| `packages/better_auth-mongo-adapter/README.md` | Document `default_find_many_limit` and default limit behavior |
| `packages/better_auth-mongo-adapter/CHANGELOG.md` | Note behavior change (breaking-ish: capped scans) |

---

## Out of scope (explicit)

| Item | Reason |
|------|--------|
| **`debugLogs` port** | Upstream passes logs through `createAdapterFactory`; Ruby has no equivalent adapter factory hook—would require core API work (YAGNI for this plan). |
| **Replica set / standalone transaction docs only** | Operational MongoDB constraint; adapter already supports `transaction: false`. No code change. |
| **`BSON::ObjectId` rescue strictness** | Tightening `bson_id` rescues could break apps that rely on passthrough values; behavior matches “best effort” upstream `serializeID`. Address only if product decides on a breaking release. |
| **`require "mongo" unless database` rewrite** | Cosmetic; tests rely on loading BSON separately—risk > reward. |

---

### Task 1: `default_find_many_limit` helper

**Files:**
- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`
- Test: `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb`

- [x] **Step 1: Write failing tests** for default limit resolution.

Add tests that instantiate `BetterAuth::Configuration.new(secret: ..., database: :memory, advanced: {database: {default_find_many_limit: 50}})` and assert the adapter uses `50` when applying defaults (you will wire this in Step 3). Until implementation exists, assert against pipeline stages—e.g. after `find_many` with `join: {session: true}` (one-to-many), `FakeMongoCollection#aggregate_pipelines` last pipeline includes `$lookup` with inner `$limit` of **50** (not unbounded simple lookup).

```ruby
def test_mongodb_join_one_to_many_uses_default_find_many_limit
  # user has many sessions; join user -> session inferred one-to-many
  # config advanced: { database: { default_find_many_limit: 3 } }
  # create 1 user + 5 sessions, find_one user with join session: true
  # expect lookup pipeline $limit 3 inside last aggregate pipeline stages
end
```

- [x] **Step 2: Run tests**

Run: `cd /Users/sebastiansala/projects/better-auth/packages/better_auth-mongo-adapter && bundle exec ruby -Itest test/better_auth/adapters/mongodb_test.rb -n test_mongodb_join_one_to_many_uses_default_find_many_limit`

Expected: FAIL (no `$limit` in pipeline or wrong value).

- [x] **Step 3: Implement private `default_find_many_limit`**

In `BetterAuth::Adapters::MongoDB` private section:

```ruby
def default_find_many_limit
  v = options.advanced.dig(:database, :default_find_many_limit)
  return 100 if v.nil?

  Integer(v)
rescue ArgumentError, TypeError
  100
end
```

- [x] **Step 4: Use limit in `join_stages`**

In `join_stages`, replace bare `limit = config[:limit]` usage with an effective limit for non-unique joins:

```ruby
effective_limit = if config[:limit] && config[:limit].to_i.positive?
  config[:limit].to_i
else
  default_find_many_limit
end
unique = relation == "one-to-one" || config[:unique]
should_limit = !unique && effective_limit.positive?
```

Keep existing `$lookup` pipeline branch when `should_limit` is true; ensure inferred joins (`join: {session: true}`) now set `should_limit` true for one-to-many with `effective_limit == default_find_many_limit`.

> **Note:** One-to-one joins remain simple `$lookup` + `$unwind` (matching upstream: `isUnique` skips pipeline syntax).

- [x] **Step 5: Run full mongo-adapter tests**

Run: `cd /Users/sebastiansala/projects/better-auth/packages/better_auth-mongo-adapter && bundle exec rake test`

Expected: PASS.

- [ ] **Step 6: Commit** (not run in this session)

```bash
git add packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb
git commit -m "fix(mongo-adapter): default capped joins via default_find_many_limit"
```

---

### Task 2: Default top-level `find_many` `$limit`

**Files:**
- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`
- Test: `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb`

- [x] **Step 1: Failing test**

Add `test_mongodb_find_many_applies_default_limit_when_omitted`: create 5 users with `force_allow_id`, call `find_many(model: "user", where: [])` **without** `limit`, capture `aggregate_pipelines`, assert final stages include `{"$limit" => 100}` when `default_find_many_limit` is default, and `{"$limit" => 7}` when config sets `7`.

> **Note:** `find_one` is unaffected because it already delegates to `find_many(..., limit: 1)`.

- [x] **Step 2: Run test** — expect FAIL until implemented.

- [x] **Step 3: Implement**

In `find_many`, after building pipeline stages for sort/skip, replace the old conditional `$limit` stage:

```ruby
effective_limit = limit.nil? ? default_find_many_limit : limit.to_i
pipeline << {"$limit" => effective_limit} if effective_limit.positive?
```

Remove or reconcile the old `pipeline << {"$limit" => limit.to_i} if limit` line to avoid duplication.

> **Edge case:** `limit: 0` is treated as “no limit” here (same as upstream `if (limit)` where `0` is falsy). Callers should use `limit: 1` if they truly need zero results.

- [x] **Step 4: Run** `bundle exec rake test` in mongo-adapter package.

- [ ] **Step 5: Commit** (not run in this session)

```bash
git commit -m "fix(mongo-adapter): default find_many limit matches upstream factory"
```

---

### Task 3: `in` / `not_in` scalar values

**Files:**
- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`
- Test: `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb`

- [x] **Step 1: Failing test**

`test_mongodb_in_operator_accepts_scalar_value`: `find_many(..., where: [{field: "id", operator: "in", value: single_id_string}])` should not raise and should emit `$in` with one element (same as upstream `mongodb-adapter.ts` lines 203–210).

- [x] **Step 2: Implement**

Remove the guard:

```ruby
if operator == "in" && !value.is_a?(Array)
  raise MongoAdapterError.new("UNSUPPORTED_OPERATOR", "Value must be an array")
end
```

For `in` / `not_in`, use `entries = Array(value)` then branch insensitive paths on `entries` (ensure `not_in` + insensitive still requires string arrays per `insensitive_value?`). For non-insensitive `in`/`not_in`, map `entries` through `store_value` as today.

- [x] **Step 3: Adjust existing test** `test_mongodb_adapter_matches_upstream_where_coercions_and_json_storage` — it currently expects `UNSUPPORTED_OPERATOR` for scalar `in` on `score` (lines 461–464). Change the assertion to expect a successful query (verify the `$match` stage contains `{"score" => {"$in" => [7]}}`).

- [ ] **Step 4: Commit** (not run in this session)

```bash
git commit -m "fix(mongo-adapter): in/not_in accept scalar values like upstream"
```

---

### Task 4: `mongo_filter` multi-clause composition (upstream buckets)

**Files:**
- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`
- Test: `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_upstream_parity_test.rb` (or `mongodb_test.rb`)

- [x] **Step 1: Failing test for bucketing**

Add a test that builds **three** clauses with mixed connectors and asserts the **exact** `$match` hash shape produced in the aggregate pipeline’s first stage matches upstream semantics:

Example clause list (adjust field names to valid user fields):

```ruby
where: [
  {field: "email", operator: "ends_with", value: "example.com"},           # connector default AND
  {field: "name", connector: "OR", value: "Grace"},                          # OR bucket
  {field: "emailVerified", value: false, connector: "AND"}                # AND bucket
]
```

Expected Mongo filter shape:

```ruby
{
  "$and" => [
    {/* email ends_with condition */},
    {"emailVerified" => false} # or storage key
  ],
  "$or" => [
    {/* name eq Grace */}
  ]
}
```

Spy on `aggregate_pipelines.last.first.first.fetch("$match")` (same style as existing tests).

- [x] **Step 2: Replace `mongo_filter` implementation**

Rewrite `mongo_filter` to:

1. Map each clause to `{condition: <hash>, connector: <"AND"|"OR">}` using `fetch_key(clause, :connector).to_s.upcase == "OR" ? "OR" : "AND"` (default AND, matching upstream line 169).
2. If one clause, return `condition` only.
3. Else build `result = {}`; push `and_conditions` and `or_conditions` arrays like upstream lines 326–339; assign `"$and" => and_conditions` if non-empty, `"$or" => or_conditions` if non-empty.

Reuse existing `condition_for` for each clause’s condition hash.

- [x] **Step 3: Update tests that asserted left-fold behavior**

Search tests for multi-clause OR/AND expectations and update them. **Specifically:**

- **`test_mongodb_adapter_supports_where_connectors_sort_limit_offset_and_count`** (`mongodb_test.rb`, lines 106–123) currently mixes AND/OR like this:

  ```ruby
  where: [
    {field: "email", operator: "ends_with", value: "example.net"},
    {field: "name", connector: "OR", value: "Grace"}
  ]
  ```

  With left-fold this produced `{ $or: [A, B] }` (returning user-3 and user-2). With bucketing it produces `{ $and: [A], $or: [B] }`, which in MongoDB means `A AND B` (returning nobody). **Fix:** change both clauses to explicit `"OR"` connectors so the intent (a true OR query) is preserved:

  ```ruby
  where: [
    {field: "email", operator: "ends_with", value: "example.net", connector: "OR"},
    {field: "name", connector: "OR", value: "Grace"}
  ]
  ```

  This keeps the expected result `["user-3", "user-2"]` unchanged while matching upstream semantics.

Document the boolean semantics change in CHANGELOG (see Task 5).

- [ ] **Step 4: Commit** (not run in this session)

```bash
git commit -m "fix(mongo-adapter): where clause AND/OR matches upstream Mongo adapter"
```

---

### Task 5: Documentation and changelog

**Files:**
- Modify: `packages/better_auth-mongo-adapter/README.md`
- Modify: `packages/better_auth-mongo-adapter/CHANGELOG.md`

- [x] **Step 1: README section** “Limits” explaining:
  - `advanced: { database: { default_find_many_limit: 100 } }` (integer; default 100 when omitted).
  - Applies to **find_many** when `limit:` kwarg is omitted and to **one-to-many join lookups** when join config does not set `limit:`.
  - Explicit `limit:` on `find_many` or on join config overrides.
  - One-to-one joins always use `limit: 1` internally and are returned as a single object or `nil`.

- [x] **Step 2: CHANGELOG** under upcoming version note **behavior changes**:
  - Unbounded `find_many` and unbounded one-to-many joins are now capped by default (100) unless overridden—callers needing full scans must pass a sufficiently large `limit` or set `default_find_many_limit` high.
  - Multi-clause `where` with mixed `AND`/`OR` connectors now uses the upstream bucket model (`$and` array + `$or` array) instead of left-fold nesting. This changes boolean semantics for queries that mixed connectors without placing all OR clauses in an explicit OR group.

- [ ] **Step 3: Commit** (not run in this session)

```bash
git commit -m "docs(mongo-adapter): document default_find_many_limit and capped queries"
```

---

## Self-review

**Spec coverage:** Tasks 1–5 map to join caps, find_many default limit, scalar `in`, AND/OR parity, and docs—all identified gaps worth shipping.

**Placeholder scan:** No TBD steps; tests include concrete assertions.

**Consistency:** Single option name `:default_find_many_limit` under `advanced[:database]` alongside existing `:generate_id`.

---

## Execution handoff

Plan saved to `.docs/plans/2026-05-03-1200--mongo-adapter-upstream-parity.md`.

**Two execution options:**

1. **Subagent-driven (recommended)** — fresh subagent per task, review between tasks (`subagent-driven-development` skill).

2. **Inline execution** — run tasks in this session with `executing-plans` checkpoints.

Which approach do you want?
