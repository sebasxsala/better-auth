# Mongo Adapter Upstream Parity Follow-Up Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:test-driven-development` for every behavior change. Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Catch the residual deltas between `packages/better_auth-mongo-adapter` and the upstream `packages/mongo-adapter` (Better Auth `v1.6.9`) that remain after `2026-04-29-mongo-adapter-upstream-parity.md`. Lock down join-limit defaults, output coercion edge cases, transaction-config semantics, and OR/AND chaining edge cases.

**Architecture:** Keep the public Ruby constructor `BetterAuth::Adapters::MongoDB.new(options, database:, ...)` stable. Adjust private helpers to mirror upstream `customTransformInput`/`customTransformOutput` and the lookup-pipeline default-limit, while preserving the existing Ruby idioms (transactional adapter clone, schema-driven storage keys, `use_plural` toggle).

**Tech Stack:** Ruby 3.4.9, Minitest, StandardRB, `mongo`/`bson` gems, Better Auth Ruby adapter contract, upstream Better Auth `packages/mongo-adapter` (v1.6.9).

---

## Summary Of Identified Deltas

The previous parity plan already implemented BSON IDs, Mongo-native CRUD, transaction adapters, and the upstream-style join config. The remaining deltas are:

1. **Connector chaining for 3+ where clauses**
   - Upstream collects all `AND` and all `OR` clauses into two arrays and emits at most one `$and` and one `$or`. Ruby's left-fold builds nested `$and`/`$or` pairs, e.g. `[a, b, c]` → `{$and: [{$and: [a, b]}, c]}` instead of `{$and: [a, b, c]}`.
   - This is functionally equivalent but the resulting query plan/diagnostics differ; tests against the exact filter shape will fail.

2. **Default lookup-pipeline limit**
   - Upstream falls back to `options.advanced?.database?.defaultFindManyLimit ?? 100` when the join config does not set a `limit`. Ruby never applies the default; if `limit` is `nil`, it uses simple `$lookup` (no inner pipeline). Result: real datasets may receive more documents than upstream.

3. **`findMany`-only relation guard**
   - In `findMany`, upstream gates `shouldLimit` with `joinConfig.relation !== "one-to-one"` (the relation hint takes precedence over the `unique` index). Ruby uses `!unique && limit > 0`, which rejects limits whenever the to-field has a unique index even if `relation: "one-to-many"` is supplied.

4. **`findOne`'s `select` projection**
   - Upstream emits `$project` before `$limit: 1`. Ruby orders pipeline stages as `match → join → project → sort → skip → limit`. For `findOne`, sorts have no effect (limit is 1 implicit), but tests asserting projection ordering may fail.
   - Additionally, Ruby strips `_id` (`projection["_id"] = 0`) when the caller's `select` does not include it. Upstream **always projects `_id: 1`** implicitly because it never sets `_id: 0`. This drops `id` from selected output unless the caller explicitly asked for `id`.

5. **`update` returning a non-null value when there is no document**
   - Upstream's `findOneAndUpdate` returns `result.value` which is `null` if the filter matched nothing. Ruby returns `nil` only if `unwrap_update_result` produced `nil`, but if Mongo returns the wrapper `{value: nil, ok: 1}` Ruby returns `nil` correctly. Verify the wrapper shape on the installed `mongo` driver version (`mongo` ≥2.18 returns the document directly, ≥2.20 returns BSON document). The current `unwrap_update_result` covers most cases; add an explicit test for "no match" returning `nil`.

6. **Custom-id behavior in `serializeID`**
   - Upstream returns the raw value for **all fields** when `customIdGen` is provided, including FK references with `references.field === "id"`. Ruby short-circuits `bson_id` only when the value is already a custom-shaped string, but still calls `BSON::ObjectId.from_string` when `strict_id: true` raises on non-hex strings. Add a test where `advanced.database.generate_id` is a Proc and a FK like `userId` stores the custom string verbatim.

7. **Array IDs in `serializeID`**
   - Upstream raises `MongoAdapterError("INVALID_ID")` when an array element is neither a string nor an existing `ObjectId`/`UUID`. Ruby silently passes through unknown types in `store_value` arrays; add an explicit test and raise.

8. **`coerceToIdType` failure handling**
   - Upstream catches the constructor failure and returns the raw string (so a non-hex string passes through). Ruby's `bson_id` returns the raw value from `rescue BSON::Error::InvalidObjectId, ArgumentError` only when `strict_id` is `false`; for `strict_id: true` it raises. This matches upstream **only** because upstream always passes through invalid IDs. Decide: keep Ruby's strict-mode raise for safety, or drop strict-mode and pass through to match upstream. Current Ruby behavior may break on legacy data.

9. **`debugLogs` upstream config**
   - Upstream accepts `debugLogs: boolean | { create?: boolean, ...per-method... }` and emits per-call traces. Ruby has no debug logging hook. The earlier plan documented this as intentionally unported, but the option key should at least be accepted (and silently ignored) so apps can pass the same config to both implementations.

10. **`transaction: false` semantics**
    - Upstream defaults transactions to `true` only when `client` is provided, else `false`. Ruby mirrors this. However, upstream's transaction adapter falls back to the lazy non-session adapter inside the callback if `config.client` is unexpectedly missing; Ruby raises if `client` is `nil`. Verify the fallback path matches upstream so apps without a client and with `transaction: true` do not error.

## File Structure

- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`
- Modify: `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb`
- Modify: `packages/better_auth-mongo-adapter/README.md` and `docs/content/docs/adapters/mongo.mdx`

## Task List

### Task 1: Failing Parity Tests

**Files:**
- Modify: `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb`

- [ ] **Step 1: Add tests for connector chaining**

```ruby
def test_mongo_filter_emits_single_and_or_arrays_for_multiple_clauses
  adapter = build_adapter
  filter = adapter.send(:mongo_filter, "user", [
    {field: "email", value: "a@a", connector: "AND"},
    {field: "name", value: "x", connector: "OR"},
    {field: "id", value: "abc", connector: "AND"}
  ])

  assert_equal 2, filter.size
  assert_equal 2, filter["$and"].size
  assert_equal 1, filter["$or"].size
end
```

- [ ] **Step 2: Add tests for default lookup limit**

```ruby
def test_find_many_join_uses_default_find_many_limit_when_unset
  options = build_options(advanced: {database: {default_find_many_limit: 25}})
  adapter = build_adapter(options: options)
  pipeline = capture_aggregate(adapter) do
    adapter.find_many(model: "user", where: [], join: {session: {on: {from: "id", to: "userId"}, relation: "one-to-many"}})
  end
  lookup = pipeline.find { |stage| stage.key?("$lookup") }["$lookup"]
  inner_limit = lookup["pipeline"].find { |stage| stage.key?("$limit") }["$limit"]
  assert_equal 25, inner_limit
end
```

- [ ] **Step 3: Add tests for relation-aware join limit gating, projection `_id` retention, custom-id FK passthrough, and array-id validation**

Mirror the upstream tests in `upstream/packages/mongo-adapter/src/mongodb-adapter.test.ts` plus the relevant cases in `upstream/packages/test-utils/src/adapter/suites/{basic,case-insensitive,uuid}.ts`.

- [ ] **Step 4: Run the new tests to verify failures**

```bash
cd packages/better_auth-mongo-adapter
rbenv exec bundle exec ruby -Itest test/better_auth/adapters/mongodb_test.rb
```

Expected: failures in the new connector chaining, default-limit, projection, and FK passthrough tests.

### Task 2: Connector Chaining Refactor

**Files:**
- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`

- [ ] **Step 1: Replace `mongo_filter` with bucketed AND/OR collection**

```ruby
def mongo_filter(model, where)
  clauses = Array(where)
  return {} if clauses.empty?

  pairs = clauses.map { |clause| [condition_for(model, clause), fetch_key(clause, :connector).to_s.upcase] }
  return pairs.first.first if pairs.length == 1

  ands = pairs.select { |(_, c)| c != "OR" }.map(&:first)
  ors  = pairs.select { |(_, c)| c == "OR" }.map(&:first)

  filter = {}
  filter["$and"] = ands if ands.any?
  filter["$or"] = ors if ors.any?
  filter
end
```

- [ ] **Step 2: Run filter tests**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/adapters/mongodb_test.rb -n /connector|where|filter/
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git commit -am "fix(mongo-adapter): bucket AND/OR clauses to match upstream filter shape"
```

### Task 3: Default Lookup Limit And Relation Gating

**Files:**
- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`

- [ ] **Step 1: Wire `default_find_many_limit` into `join_stages`**

```ruby
def join_stages(model, join)
  default_limit = options.advanced.dig(:database, :default_find_many_limit)
  normalized_join(model, join).flat_map do |join_model, config|
    local_field   = storage_field_for_join(model, config.fetch(:from))
    foreign_field = storage_field_for_join(join_model, config.fetch(:to))
    relation = config[:relation]
    unique = relation == "one-to-one" || (config[:unique] && relation != "one-to-many")
    limit = config[:limit] || default_limit || 100
    should_limit = relation != "one-to-one" && (config[:limit] || default_limit)

    lookup = if should_limit && limit.to_i.positive?
      {"$lookup" => {
        "from" => collection_name(join_model),
        "let" => {"localFieldValue" => "$#{local_field}"},
        "pipeline" => [
          {"$match" => {"$expr" => {"$eq" => ["$#{foreign_field}", "$$localFieldValue"]}}},
          {"$limit" => limit.to_i}
        ],
        "as" => join_model
      }}
    else
      {"$lookup" => {
        "from" => collection_name(join_model),
        "localField" => local_field,
        "foreignField" => foreign_field,
        "as" => join_model
      }}
    end

    unique ? [lookup, {"$unwind" => {"path" => "$#{join_model}", "preserveNullAndEmptyArrays" => true}}] : [lookup]
  end
end
```

Note the `relation != "one-to-many"` clause keeps the Ruby behavior of unwinding when the FK is unique unless the caller explicitly says one-to-many.

- [ ] **Step 2: Run join tests**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/adapters/mongodb_test.rb -n /join|lookup/
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git commit -am "fix(mongo-adapter): respect defaultFindManyLimit and relation hints in joins"
```

### Task 4: Projection And Output Coercion Parity

**Files:**
- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`

- [ ] **Step 1: Stop force-suppressing `_id` in projection**

In `projection_for`, drop the `projection["_id"] = 0 unless selected_fields.include?("_id")` line. Upstream never sets `_id: 0` and tests rely on receiving the document id even when only specific fields are selected.

- [ ] **Step 2: Validate array-id elements**

In `store_value` (under `id_field?`), when the value is an Array, raise `MongoAdapterError.new("INVALID_ID", "Invalid id value")` for non-string, non-BSON entries instead of silently passing them through.

- [ ] **Step 3: Custom-id generator FK passthrough**

In `store_value`, return the raw value for any field where `id_field?(field, attributes)` and `custom_id_generator?` is true, including arrays of strings. Mirror upstream's `serializeID` early-return.

- [ ] **Step 4: Run the relevant tests**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/adapters/mongodb_test.rb -n /select|projection|custom_id|array_id/
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git commit -am "fix(mongo-adapter): keep _id in projection and validate array id values"
```

### Task 5: Transaction Fallback And Debug Option Compatibility

**Files:**
- Modify: `packages/better_auth-mongo-adapter/lib/better_auth/mongo_adapter.rb`
- Modify: `packages/better_auth-mongo-adapter/test/better_auth/adapters/mongodb_test.rb`

- [ ] **Step 1: Failing test that calls `transaction { ... }` without a client**

Assert that the block runs against the same adapter (no exception, no session) when `client` is `nil` and `transaction: true` is forced. Match upstream's "fall back to lazy adapter" behavior.

- [ ] **Step 2: Implement the fallback**

```ruby
def transaction
  return yield self unless @transaction_enabled
  return yield self unless client && client.respond_to?(:start_session)

  session = client.start_session
  begin
    session.start_transaction
    adapter = self.class.new(options, database: database, client: client, transaction: @transaction_enabled, use_plural: use_plural, session: session)
    result = yield adapter
    session.commit_transaction
    result
  rescue
    session.abort_transaction
    raise
  ensure
    session.end_session
  end
end
```

- [ ] **Step 3: Accept `debug_logs` config option**

In `initialize`, accept a `debug_logs:` keyword that is stored but unused (so upstream apps can pass the same options object). Add a documentation note that the Ruby adapter currently does not emit per-method debug traces.

- [ ] **Step 4: Run transaction tests**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/adapters/mongodb_test.rb -n /transaction|debug/
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(mongo-adapter): no-client transaction fallback and accept debug_logs option"
```

### Task 6: Documentation Refresh And Final Verification

**Files:**
- Modify: `packages/better_auth-mongo-adapter/README.md`
- Modify: `docs/content/docs/adapters/mongo.mdx`

- [ ] **Step 1: Update docs**

Note in both files:

- New connector behavior emits a single `$and` and a single `$or`.
- `default_find_many_limit` (advanced.database) cascades into `$lookup` pipelines for joins without an explicit limit.
- `_id` is always projected; specify it in `select` only when callers explicitly want a typed ObjectId/UUID instead of the string id.
- `transaction: true` without a client falls back to non-transactional execution.
- `debug_logs` is accepted for upstream parity but not yet wired (still considered a Ruby-specific intentional gap).

- [ ] **Step 2: Run the full suite**

```bash
cd packages/better_auth-mongo-adapter
rbenv exec bundle exec rake test
RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb
```

Expected: tests + lint pass; real-mongo tests skip when no Mongo service is available.

- [ ] **Step 3: Run the core shim regression**

```bash
cd ../better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/adapters/mongodb_external_shim_test.rb
```

Expected: PASS.

- [ ] **Step 4: Update the verification log section of this plan with run counts**

- [ ] **Step 5: Commit**

```bash
git commit -am "docs(mongo-adapter): document upstream parity follow-ups"
```

## Assumptions

- Better Auth core's `Configuration` already exposes `advanced.database.default_find_many_limit`; if not, this plan adds the option to the core config before wiring.
- Behaviorally identical filter shapes are not strictly required by the SDK contract but are required by adapter-suite tests that snapshot the produced query.
- Real-mongo replica-set tests continue to be opt-in via `BETTER_AUTH_MONGO_REPLICA_SET_URL`.

## Open Questions

- Should the Ruby adapter implement upstream-style debug logging, or should it stay an explicit gap? The previous plan explicitly chose the latter; revisit if downstream demand justifies it.
- Does any existing app rely on the `_id: 0` projection currently emitted by Ruby? If yes, gate the change on a backwards-compat flag before merging.
