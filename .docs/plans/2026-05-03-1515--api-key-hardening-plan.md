# API Key package hardening (parity + ops)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align expired-key cleanup with upstream `deleteMany` semantics, make failure responses JSON-safe, improve observability when secondary-storage reference indexes are corrupt, and document operational limits that are intentional or environment-dependent.

**Architecture:** Changes stay inside `packages/better_auth-api-key` (implementation + tests + gem README) and `.docs/features/api-key.md` for discoverability. Expired cleanup uses the existing `BetterAuth::Adapter#delete_many` contract already implemented by SQL and memory adapters (`operator: "lt"` / `"ne"`).

**Tech Stack:** Ruby, Minitest, StandardRB, existing `better_auth` adapter API.

---

## Out of scope (with rationale)

These items came from the analysis but **must not** be implemented as code here:


| Item                                                                           | Rationale                                                                                                |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| Parity with TypeScript `apiKeyClient()`                                        | Client-side package; Ruby exposes the HTTP contract only (already documented in the gem README).         |
| Change `KEY_NOT_FOUND` on permission denial                                    | Matches upstream obscurity; distinguishing authz vs missing key would leak information.                  |
| Distributed coordination for the 10s cleanup throttle                          | Would require Redis or similar outside this gem; ops/deployment concern.                                 |
| Organization-reference keys establishing browser sessions                      | Upstream explicitly rejects (`INVALID_REFERENCE_ID_FROM_API_KEY`); changing would diverge from upstream. |
| Strong serialization / locking for `remaining` + rate limits under concurrency | Large cross-cutting change; belongs to a dedicated concurrency design. Document only.                    |
| Automatic purge of expired keys from secondary-only Redis                      | Same class of limitation as upstream (DB `deleteMany` does not touch KV); rely on TTL + ops; document.   |


---

## File map


| File                                                                                               | Role                                                                           |
| -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `packages/better_auth-api-key/lib/better_auth/api_key/routes/index.rb`                             | Replace in-memory full scan with `delete_many` where-clause (upstream parity). |
| `packages/better_auth-api-key/lib/better_auth/api_key/routes/delete_all_expired_api_keys.rb`       | Serialize errors as JSON-friendly hashes.                                      |
| `packages/better_auth-api-key/lib/better_auth/api_key/adapter.rb`                                  | Warn when reference-index JSON is corrupt (secondary storage).                 |
| `packages/better_auth-api-key/test/better_auth/api_key/routes/index_test.rb`                       | Assert selective deletion (`expiresAt` nil preserved, future preserved).       |
| `packages/better_auth-api-key/test/better_auth/api_key/routes/delete_all_expired_api_keys_test.rb` | Assert error payload shape on failure.                                         |
| `packages/better_auth-api-key/test/better_auth/api_key/adapter_test.rb`                            | Assert warning path when reference JSON is invalid (capture logger).           |
| `packages/better_auth-api-key/README.md`                                                           | Short “Operational notes” subsection.                                          |
| `.docs/features/api-key.md`                                                                        | Same caveats for repo-wide discoverability.                                    |


---

### Task 1: Expired cleanup uses `delete_many` (upstream parity)

**Files:**

- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/routes/index.rb` (`Routes.delete_expired`)
- Modify: `packages/better_auth-api-key/test/better_auth/api_key/routes/index_test.rb`
- [x] **Step 1: Add regression test + helpers for selective deletion**

Place `test_delete_expired_uses_adapter_delete_many_semantics` **above** the existing `private` keyword in `index_test.rb`. Add `base_api_key_row` **inside** the existing `private` section next to `create_expired_record`, then refactor `create_expired_record` to:

```ruby
  def create_expired_record(auth, key)
    now = Time.now
    auth.context.adapter.create(model: "apikey", data: base_api_key_row(key, now - 60, reference_id: "reference-id"))
  end
```

Append the new test:

```ruby
  def test_delete_expired_uses_adapter_delete_many_semantics
    auth = build_api_key_auth(default_key_length: 12)
    config = BetterAuth::APIKey::Configuration.normalize({})
    now = Time.now

    expired = auth.context.adapter.create(
      model: "apikey",
      data: base_api_key_row("expired", now - 120, reference_id: "r1")
    )
    future = auth.context.adapter.create(
      model: "apikey",
      data: base_api_key_row("future", now + 3600, reference_id: "r2")
    )
    no_expiry = auth.context.adapter.create(
      model: "apikey",
      data: base_api_key_row("no-expiry", nil, reference_id: "r3")
    )

    BetterAuth::APIKey::Routes.delete_expired(auth.context, config, bypass_last_check: true)

    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: expired.fetch("id")}])
    refute_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: future.fetch("id")}])
    refute_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: no_expiry.fetch("id")}])
  end
```

Private helpers:

```ruby
  def base_api_key_row(key_material, expires_at, reference_id:)
    now = Time.now
    {
      configId: "default",
      createdAt: now,
      updatedAt: now,
      name: nil,
      prefix: nil,
      start: key_material.to_s[0, 6],
      key: key_material,
      enabled: true,
      expiresAt: expires_at,
      referenceId: reference_id,
      lastRefillAt: nil,
      lastRequest: nil,
      metadata: nil,
      rateLimitMax: 10,
      rateLimitTimeWindow: 86_400_000,
      remaining: nil,
      refillAmount: nil,
      refillInterval: nil,
      rateLimitEnabled: true,
      requestCount: 0,
      permissions: nil
    }
  end
```

- [x] **Step 2: Run the new test only**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-api-key
bundle exec ruby -Itest test/better_auth/api_key/routes/index_test.rb -n test_delete_expired_uses_adapter_delete_many_semantics
```

Expected: **PASS** with the current full-scan implementation (behavior already matches). Step 3 is for **DB-side filtering / parity**, not fixing wrong deletes.

- [x] **Step 3: Implement `delete_expired` with `delete_many`**

Replace the body of `delete_expired` in `routes/index.rb` (keep throttle and early `return unless storage` gate) with:

```ruby
      def delete_expired(context, config, bypass_last_check: false)
        return unless config[:storage] == "database" || config[:fallback_to_database]
        unless bypass_last_check
          now = Time.now
          return if @last_expired_check && ((now - @last_expired_check) * 1000) < 10_000

          @last_expired_check = now
        end

        now = Time.now
        context.adapter.delete_many(
          model: BetterAuth::Plugins::API_KEY_TABLE_NAME,
          where: [
            {field: "expiresAt", value: now, operator: "lt"},
            {field: "expiresAt", value: nil, operator: "ne"}
          ]
        )
      end
```

- [x] **Step 4: Run full api-key route tests**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-api-key
bundle exec ruby -Itest test/better_auth/api_key/routes/index_test.rb
```

Expected: **PASS**

- [x] **Step 5: Commit**

Completed without committing because `packages/better_auth/AGENTS.md` says not
to commit unless explicitly asked. During verification, this exposed a
Ruby-specific core memory adapter gap: range operators raised on nil record
values before the `ne nil` clause could exclude them. Added coverage in
`packages/better_auth/test/better_auth/adapters/memory_test.rb` and updated
`packages/better_auth/lib/better_auth/adapters/memory.rb` so `gt/gte/lt/lte`
return false when the record value is nil.

```bash
git add packages/better_auth-api-key/lib/better_auth/api_key/routes/index.rb packages/better_auth-api-key/test/better_auth/api_key/routes/index_test.rb
git commit -m "perf(api-key): delete expired keys via adapter delete_many"
```

---

### Task 2: JSON-safe errors on `delete-all-expired`

**Files:**

- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/routes/delete_all_expired_api_keys.rb`
- Modify: `packages/better_auth-api-key/test/better_auth/api_key/routes/delete_all_expired_api_keys_test.rb`
- [x] **Step 1: Write failing test**

Extend `delete_all_expired_api_keys_test.rb`:

```ruby
  def test_delete_all_expired_returns_serializable_error_payload
    auth = build_api_key_auth(default_key_length: 12)
    auth.context.adapter.define_singleton_method(:delete_many) do |**|
      raise StandardError, "simulated adapter failure"
    end

    result = auth.api.delete_all_expired_api_keys

    assert_equal false, result.fetch(:success)
    err = result.fetch(:error)
    assert err.is_a?(Hash)
    assert_equal "simulated adapter failure", err.fetch(:message)
    assert_equal "StandardError", err.fetch(:name)
  end
```

If `auth.api.delete_all_expired_api_keys` does not hit `delete_many` on the adapter instance used by `delete_expired`, adjust the stub target (the object’s `context.adapter`) after reading `build_api_key_auth` wiring — the stub must trigger inside `Routes.delete_expired`.

- [x] **Step 2: Run test — expect FAIL** until implementation.

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-api-key
bundle exec ruby -Itest test/better_auth/api_key/routes/delete_all_expired_api_keys_test.rb -n test_delete_all_expired_returns_serializable_error_payload
```

- [x] **Step 3: Implement error serialization**

In `delete_all_expired_api_keys.rb`, replace the `rescue` body with:

```ruby
          rescue => error
            ctx.context.logger.error("[API KEY PLUGIN] Failed to delete expired API keys: #{error.message}") if ctx.context.logger.respond_to?(:error)
            payload = {message: error.message.to_s, name: error.class.name}
            ctx.json({success: false, error: payload})
          end
```

- [x] **Step 4: Run tests**

```bash
bundle exec ruby -Itest test/better_auth/api_key/routes/delete_all_expired_api_keys_test.rb
```

Expected: **PASS**

- [x] **Step 5: Commit**

Completed without committing because commits were not explicitly requested.

```bash
git add packages/better_auth-api-key/lib/better_auth/api_key/routes/delete_all_expired_api_keys.rb packages/better_auth-api-key/test/better_auth/api_key/routes/delete_all_expired_api_keys_test.rb
git commit -m "fix(api-key): return JSON-safe errors from delete-all-expired route"
```

---

### Task 3: Log corrupt secondary-storage reference index

**Files:**

- Modify: `packages/better_auth-api-key/lib/better_auth/api_key/adapter.rb` (`list_for_reference`)
- Modify: `packages/better_auth-api-key/test/better_auth/api_key/adapter_test.rb`

- [x] **Step 1: Add this test to `adapter_test.rb`**

```ruby
  def test_list_for_reference_warns_on_corrupt_reference_index_json
    storage = APIKeyTestSupport::MemoryStorage.new
    ref = "user-corrupt"
    storage.set(BetterAuth::APIKey::Adapter.storage_key_by_reference(ref), "{bad")

    warnings = []
    logger = Object.new
    logger.define_singleton_method(:warn) { |msg| warnings << msg }

    auth = build_api_key_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      fallback_to_database: false,
      default_key_length: 12
    )
    auth.context.define_singleton_method(:logger) { logger }

    ctx = Struct.new(:context).new(auth.context)
    config = BetterAuth::APIKey::Configuration.normalize({})[:configurations].first
    config = config.merge(storage: "secondary-storage", fallback_to_database: false)

    result = BetterAuth::APIKey::Adapter.list_for_reference(ctx, ref, config)

    assert_equal [], result
    assert_equal 1, warnings.length
    assert_match(/Corrupt api-key reference index/i, warnings.first)
  end
```

- [x] **Step 2: Run test — expect FAIL** until `list_for_reference` logs a warning (assertion on `warnings`).

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-api-key
bundle exec ruby -Itest test/better_auth/api_key/adapter_test.rb -n test_list_for_reference_warns_on_corrupt_reference_index_json
```

- [x] **Step 3: In `list_for_reference` `rescue`**, bind `error`, and before `return [] unless config[:fallback_to_database]`:

```ruby
            if ctx.context.respond_to?(:logger) && ctx.context.logger.respond_to?(:warn)
              ctx.context.logger.warn(
                "[API KEY PLUGIN] Corrupt api-key reference index for #{reference_id.inspect}: #{error.class}: #{error.message}"
              )
            end
```

Ensure the inner `begin` uses `rescue JSON::ParserError, NoMethodError => error` so `error` is in scope for logging.

- [x] **Step 4: Run adapter tests**

```bash
bundle exec ruby -Itest test/better_auth/api_key/adapter_test.rb
```

- [x] **Step 5: Commit**

Completed without committing because commits were not explicitly requested.

```bash
git add packages/better_auth-api-key/lib/better_auth/api_key/adapter.rb packages/better_auth-api-key/test/better_auth/api_key/adapter_test.rb
git commit -m "chore(api-key): warn when secondary reference index JSON is corrupt"
```

---

### Task 4: Documentation (operational limits)

**Files:**

- Modify: `packages/better_auth-api-key/README.md`
- Modify: `.docs/features/api-key.md`

- [x] **Step 1: Insert “Operational notes”** after existing “Notes” or “Upstream parity” in `packages/better_auth-api-key/README.md` (~10–15 lines). Cover at least:

  - Expired-row cleanup runs against the **database** when `storage` is `database` or `fallback_to_database` is true; align TTL on Redis for secondary-only keys.
  - The ~10s throttle for scheduled cleanup is **per process** (not coordinated across workers).
  - `defer_updates` plus `advanced.background_tasks.handler` can reorder usage updates under concurrency.

- [x] **Step 2: Append `## Operational notes`** at the end of `.docs/features/api-key.md` with the same three ideas (can reference the gem README path).

- [x] **Step 3: Commit docs**

Completed without committing because commits were not explicitly requested.

```bash
git add packages/better_auth-api-key/README.md .docs/features/api-key.md
git commit -m "docs(api-key): document cleanup scope and multi-process behavior"
```

---

### Task 5: Package CI / lint

- [x] **Step 1: From gem directory**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-api-key
bundle exec standardrb
bundle exec ruby -Itest test/better_auth/api_key_test.rb
```

Expected: **PASS** (or fix offenses).

- [x] **Step 2: Final commit** if any lint fixes were needed.

No lint fixes were needed and no commit was created because commits were not
explicitly requested.

---

## Self-review (plan author)

1. **Spec coverage:** Expired cleanup parity, JSON errors, corrupt-index observability, docs for excluded distributed/concurrency topics — all mapped.
2. **Placeholder scan:** No TBD steps; test code is concrete.
3. **Consistency:** `API_KEY_TABLE_NAME` / `"apikey"` model name matches `BetterAuth::Plugins::API_KEY_TABLE_NAME` used elsewhere.

---

**Plan complete and saved to `.docs/plans/2026-05-03-1515--api-key-hardening-plan.md`.**

**Execution options:**

1. **Subagent-driven (recommended)** — Fresh subagent per task, review between tasks; **REQUIRED SUB-SKILL:** `superpowers:subagent-driven-development`.
2. **Inline execution** — Run tasks in this session with checkpoints; **REQUIRED SUB-SKILL:** `superpowers:executing-plans`.

**Which approach?**
