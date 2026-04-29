# Redis Storage Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining Better Auth upstream `@better-auth/redis-storage` (v1.6.9) deltas in the Ruby `better_auth-redis-storage` port so the public API, return contracts, edge-case behavior, and documentation match upstream, with deviations documented and locked behind tests.

**Architecture:** Treat `upstream/packages/redis-storage/src/redis-storage.ts` as the source of truth for the secondary-storage contract (`get`, `set`, `delete`, `listKeys`, `clear`). The Ruby gem exposes a `BetterAuth::RedisStorage` class with `redisStorage`-equivalent semantics. The gem stays a thin wrapper around any redis client that responds to `#get`, `#set(key, value)`, `#setex(key, ttl, value)`, `#del(*keys)`, `#keys(pattern)` (matches `redis` and `redis-namespace` gems and any test fake). Browser-only client helpers and TypeScript-only typings are out of scope; surface gem-level Ruby idioms (`#listKeys` alias, `#build` factory) but keep behavior bug-for-bug compatible.

**Tech Stack:** Ruby 3.4.9, Minitest, StandardRB, the `redis` gem (`~> 5`), Better Auth core `SecondaryStorage` contract (`get`, `set`, `delete`, optional `listKeys`/`clear`).

---

## Summary

The Ruby implementation is functionally close to upstream and even covers the optional `listKeys`/`clear` extension. The remaining deltas are:

1. **Public factory shape:** Upstream exports a `redisStorage(config)` *function* that returns an object literal. Ruby exposes a `BetterAuth::RedisStorage.new(...)` class. Add a `BetterAuth.redis_storage(client:, key_prefix:)` module-level builder (and a `BetterAuth::RedisStorage.redisStorage` camelCase alias) so docs and call sites can mirror upstream wording.
2. **`clear` is unsafe when no keys match:** Upstream calls `client.del(...keys)` which crashes when `keys` is empty (`ERR wrong number of arguments`). Ruby guards against the empty case (`unless keys.empty?`). Lock the safer Ruby behavior with a regression test and document the intentional deviation.
3. **`listKeys` may explode on large databases.** Upstream uses `KEYS pattern` (O(N), blocking). Ruby mirrors that exactly. Add a documented `scan: true` option that uses `SCAN` instead and keep `KEYS` as the default to preserve parity.
4. **`set(key, value, ttl)` should accept `ttl: 0` and `ttl: -1` like upstream.** Upstream falls back to `set` when `ttl > 0` is false. Ruby agrees, but does not coerce string/`Float` TTLs the way callers might expect (`"60"` should be treated as 60). Lock numeric coercion explicitly with tests.
5. **Plugin metadata exposure (gem-level):** Add `BetterAuth::RedisStorage::VERSION` to the value returned by `BetterAuth.redis_storage(...)` and document that it is the gem version, not the upstream one. Mirror the upstream `@better-auth/redis-storage` README structure under `packages/better_auth-redis-storage/README.md`.
6. **Async return-value contract:** Upstream's `set` and `delete` return `Promise<void>`; Ruby returns `nil`. Document the difference. Tests should assert `nil` for the Ruby return value but never assert `true`/`false`.
7. **Test fake parity:** The current `FakeRedisClient` correctly emulates `setex` and `del`. Add explicit assertions that empty `listKeys` does not raise, that pipelined writes maintain insertion order through the public API, and that prefixed keys never bleed into non-prefixed keys (mirrors upstream's `keyPrefix` contract).
8. **Real Redis integration test gating:** The current test only runs when `REDIS_URL` is set. Convert the real-Redis integration test into a `tagged` test suite (`REDIS_INTEGRATION=1`) and ensure both the in-memory and Redis path exercise rate limiting (`storage: "secondary-storage"`) and active-session indexing through `BetterAuth.auth(...)`.
9. **Documentation:** Document the gem's intentional Ruby adaptations (camelCase alias, `clear` safety, optional `scan: true`) and the upstream-compatible call patterns (`BetterAuth.redis_storage(client: redis)`).

The plan is small (the file is ~70 lines), so the bulk of work is regression coverage and documentation.

## Key Changes

- **Module-level builder:** Add `BetterAuth.redis_storage(client:, key_prefix:)` and a `BetterAuth::RedisStorage.redisStorage(config)` class-method alias.
- **TTL coercion:** In `set`, coerce `ttl` via `Integer(ttl, exception: false)` and only call `setex` when the result is positive. Negative or non-numeric values fall through to `set`.
- **`clear` safety:** Keep the existing empty-keys guard but explicitly document and test it.
- **`listKeys` SCAN opt-in:** Add an `scan_count: Integer | nil` constructor option and a `BetterAuth::RedisStorage::SCAN_DEFAULT_COUNT = 100` constant. When `scan_count` is set, replace `client.keys` with a `SCAN` loop. Default remains `KEYS` to match upstream.
- **`SecondaryStorage` interface assertion:** Document the four-method contract (`get`, `set`, `delete`, optional `listKeys`/`clear`) so adopters know what is required when supplying a custom secondary storage backend.
- **Compatibility tests:** Add tests covering rate-limit storage, active-session entries, session payload reads, and verification storage when `secondary_storage:` points at the gem with `store_session_in_database: false`.
- **Real Redis integration:** Move the real-Redis test under a separate Minitest `Suite` (`RedisStorageIntegrationTest`) gated on `REDIS_INTEGRATION=1`, exercise both `store_session_in_database: true|false`, exercise rate-limiting under `secondary-storage`, and assert that prefix isolation prevents cross-app bleeding.

## File Structure

| File | Responsibility | Action |
| --- | --- | --- |
| `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb` | `BetterAuth::RedisStorage` class implementing the secondary-storage contract. | Modify: add factory aliases, TTL coercion, optional `scan_count`, `redisStorage` class-method alias. |
| `packages/better_auth-redis-storage/lib/better_auth/redis_storage/version.rb` | Gem version. | No change unless we cut a release. |
| `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb` | Existing Minitest suite covering `set`/`get`/`setex`/`delete`/`list_keys`/`clear`. | Modify: add new failing tests for each parity gap before implementation; split out the real-Redis integration test. |
| `packages/better_auth-redis-storage/test/better_auth/redis_storage_integration_test.rb` | New file: real-Redis integration test. | Create. |
| `packages/better_auth-redis-storage/test/test_helper.rb` | Loads gem + Minitest config. | Possibly modify to register a `:integration` Minitest tag. |
| `packages/better_auth-redis-storage/README.md` | Adopter-facing docs. | Modify: document upstream-compatible call shape, optional `scan_count`, `clear` safety, return-value contract, and test gating. |
| `.docs/features/upstream-parity-matrix.md` | Repo-wide parity tracker. | Modify: bump `redis-storage` to "100%" once Task 8 verification log is complete. |

The single Ruby source file stays under 100 lines; we will not split it. Tests grow from 1 file to 2 (unit + integration) — splitting matches the integration-vs-unit responsibility boundary.

---

## Task List

### Task 1: Save Plan And Establish Baseline

- [ ] Create `.docs/plans/2026-04-29-redis-storage-upstream-parity.md` with this plan.
- [ ] Run `git status --short --branch` and confirm work is on a dedicated branch (e.g. `codex/redis-storage-upstream-diff`).
- [ ] Initialize upstream at `v1.6.9`:

```bash
git submodule update --init --recursive upstream
cd upstream && git fetch --tags origin && git checkout v1.6.9 && cd ..
```

- [ ] Run baseline package tests: `cd packages/better_auth-redis-storage && rbenv exec bundle exec rake test`.
- [ ] Record baseline run counts and any pre-existing failures in this plan's Verification Log section.

### Task 2: Module-Level `redis_storage` Builder

**Files:**
- Modify: `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb`
- Modify: `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb`
- Verify: `upstream/packages/redis-storage/src/redis-storage.ts:37-75`

- [ ] **Step 1: Add a failing test for the upstream-compatible call shape**

```ruby
def test_module_level_redis_storage_builder_returns_storage_instance
  client = FakeRedisClient.new
  storage = BetterAuth.redis_storage(client: client, key_prefix: "auth:")

  assert_instance_of BetterAuth::RedisStorage, storage
  assert_equal "auth:", storage.key_prefix

  storage.set("k", "v")
  assert_equal "v", client.data.fetch("auth:k")
end

def test_camel_case_redis_storage_class_method_alias_matches_upstream_name
  client = FakeRedisClient.new
  storage = BetterAuth::RedisStorage.redisStorage(client: client)
  assert_instance_of BetterAuth::RedisStorage, storage
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth-redis-storage && rbenv exec bundle exec ruby -Itest test/better_auth/redis_storage_test.rb -n /redis_storage_(builder|class_method_alias)/`

Expected: FAIL with `NoMethodError: undefined method 'redis_storage' for BetterAuth` and `NoMethodError: undefined method 'redisStorage' for BetterAuth::RedisStorage`.

- [ ] **Step 3: Implement the builders**

In `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb`:

```ruby
module BetterAuth
  def self.redis_storage(client:, key_prefix: BetterAuth::RedisStorage::DEFAULT_KEY_PREFIX)
    BetterAuth::RedisStorage.new(client: client, key_prefix: key_prefix)
  end

  class RedisStorage
    def self.redisStorage(client:, key_prefix: DEFAULT_KEY_PREFIX)
      new(client: client, key_prefix: key_prefix)
    end
  end
end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth-redis-storage && rbenv exec bundle exec ruby -Itest test/better_auth/redis_storage_test.rb -n /redis_storage_(builder|class_method_alias)/`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb \
        packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb
git commit -m "feat(redis-storage): expose module-level builder mirroring upstream redisStorage()"
```

### Task 3: TTL Coercion And Edge-Case Parity

**Files:**
- Modify: `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb`
- Modify: `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb`
- Verify: `upstream/packages/redis-storage/src/redis-storage.ts:49-55`

- [ ] **Step 1: Add failing tests**

```ruby
def test_set_treats_string_ttl_as_seconds_when_positive
  @storage.set("string-ttl", "payload", "60")

  assert_equal [["better-auth:string-ttl", 60, "payload"]], @client.setex_calls
end

def test_set_falls_back_to_plain_set_for_non_numeric_or_negative_ttl
  @storage.set("bad-ttl", "payload", "abc")
  @storage.set("neg-ttl", "payload", -5)
  @storage.set("float-zero-ttl", "payload", 0.0)

  assert_equal [
    ["better-auth:bad-ttl", "payload"],
    ["better-auth:neg-ttl", "payload"],
    ["better-auth:float-zero-ttl", "payload"]
  ], @client.set_calls
end

def test_set_with_float_positive_ttl_truncates_to_integer
  @storage.set("float-ttl", "payload", 1.9)

  assert_equal [["better-auth:float-ttl", 1, "payload"]], @client.setex_calls
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth-redis-storage && rbenv exec bundle exec ruby -Itest test/better_auth/redis_storage_test.rb -n /set_(treats_string_ttl|falls_back_to_plain_set|with_float_positive)/`

Expected: FAIL on the string-ttl case (Ruby currently treats `"60"` as zero) and the float case (`1.9.to_i.positive?` works but the final value is fine — verify the string-coercion path).

- [ ] **Step 3: Implement TTL coercion**

```ruby
def set(key, value, ttl = nil)
  prefixed_key = prefix_key(key)
  coerced = coerce_ttl(ttl)
  if coerced
    client.setex(prefixed_key, coerced, value)
  else
    client.set(prefixed_key, value)
  end
  nil
end

private

def coerce_ttl(ttl)
  return nil if ttl.nil?
  numeric = case ttl
  when Integer
    ttl
  when Float
    ttl.to_i
  when String
    Integer(ttl, exception: false)
  else
    nil
  end
  numeric&.positive? ? numeric : nil
end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth-redis-storage && rbenv exec bundle exec ruby -Itest test/better_auth/redis_storage_test.rb -n /set_(treats_string_ttl|falls_back_to_plain_set|with_float_positive)/`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb \
        packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb
git commit -m "fix(redis-storage): coerce numeric/string TTLs and lock zero/negative fall-through"
```

### Task 4: `clear` Empty-Keys Safety Lock

**Files:**
- Modify: `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb`
- Verify: `upstream/packages/redis-storage/src/redis-storage.ts:67-70`

- [ ] **Step 1: Add a failing/regression test**

```ruby
def test_clear_does_not_call_del_when_no_keys_match
  result = @storage.clear

  assert_nil result
  assert_empty @client.del_calls
end
```

- [ ] **Step 2: Run the test**

Run: `cd packages/better_auth-redis-storage && rbenv exec bundle exec ruby -Itest test/better_auth/redis_storage_test.rb -n test_clear_does_not_call_del_when_no_keys_match`

Expected: PASS (Ruby already guards against empty `keys`). The point is to lock the deviation from upstream behind a test; if it fails, restore the empty-array guard.

- [ ] **Step 3: Document the deviation in code**

In `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb#clear`, add a comment that explains why the Ruby version guards `keys.empty?` (avoids `ERR wrong number of arguments for 'del'` when no prefixed keys exist). Keep the implementation as-is.

- [ ] **Step 4: Commit**

```bash
git add packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb \
        packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb
git commit -m "test(redis-storage): lock empty-keys guard for clear() (intentional deviation)"
```

### Task 5: Optional SCAN-Based `list_keys` (`scan_count`)

**Files:**
- Modify: `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb`
- Modify: `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb`
- Verify: `upstream/packages/redis-storage/src/redis-storage.ts:62-65`

- [ ] **Step 1: Add a failing test for the new `scan_count` option**

```ruby
def test_list_keys_uses_scan_when_scan_count_is_provided
  scan_client = ScanCapableFakeRedisClient.new
  scan_client.set("better-auth:a", "one")
  scan_client.set("better-auth:b", "two")
  scan_client.set("other:c", "three")

  storage = BetterAuth::RedisStorage.new(client: scan_client, scan_count: 50)
  assert_equal ["a", "b"], storage.list_keys.sort

  assert_empty scan_client.keys_calls
  assert_equal [["0", {match: "better-auth:*", count: 50}]], scan_client.scan_calls.first(1)
end
```

Add a `ScanCapableFakeRedisClient` near `FakeRedisClient` that supports `#scan(cursor, match:, count:)` returning `[next_cursor_string, [keys]]` and tracks calls under `scan_calls` and `keys_calls`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/better_auth-redis-storage && rbenv exec bundle exec ruby -Itest test/better_auth/redis_storage_test.rb -n test_list_keys_uses_scan_when_scan_count_is_provided`

Expected: FAIL with `NoMethodError: undefined method 'scan_count'` or `keys_calls` non-empty.

- [ ] **Step 3: Implement `scan_count`**

```ruby
def initialize(client:, key_prefix: DEFAULT_KEY_PREFIX, scan_count: nil)
  @client = client
  @key_prefix = key_prefix.nil? ? DEFAULT_KEY_PREFIX : key_prefix.to_s
  @scan_count = scan_count
end

def list_keys
  return scan_keys.map { |key| unprefix_key(key) } if @scan_count

  client.keys("#{key_prefix}*").map { |key| unprefix_key(key) }
end

private

def scan_keys
  cursor = "0"
  matches = []
  loop do
    cursor, keys = client.scan(cursor, match: "#{key_prefix}*", count: @scan_count)
    matches.concat(keys)
    break if cursor == "0"
  end
  matches
end
```

Update `clear` to use the same pattern when `@scan_count` is set:

```ruby
def clear
  keys = @scan_count ? scan_keys : client.keys("#{key_prefix}*")
  client.del(*keys) unless keys.empty?
  nil
end
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/better_auth-redis-storage && rbenv exec bundle exec ruby -Itest test/better_auth/redis_storage_test.rb -n test_list_keys_uses_scan_when_scan_count_is_provided`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb \
        packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb
git commit -m "feat(redis-storage): add optional scan_count to use SCAN over KEYS"
```

### Task 6: SecondaryStorage Contract Compatibility Tests

**Files:**
- Modify: `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb`
- Verify: `upstream/packages/redis-storage/src/redis-storage.ts:71-75`, `packages/better_auth/lib/better_auth/adapters/internal_adapter.rb:30-160`, `packages/better_auth/lib/better_auth/rate_limiter.rb:140-180`

- [ ] **Step 1: Add failing tests against the in-memory adapter**

```ruby
def test_secondary_storage_can_back_session_payload_when_session_not_in_database
  storage = BetterAuth::RedisStorage.new(client: FakeRedisClient.new)
  auth = BetterAuth.auth(
    base_url: "http://localhost:3000",
    secret: "redis-storage-secret-with-enough-entropy-12345",
    database: :memory,
    secondary_storage: storage,
    session: {store_session_in_database: false}
  )
  result = auth.api.sign_up_email(body: {email: "session-fake@example.com", password: "password123", name: "Fake User"})

  assert result[:token]
  session_keys = storage.list_keys.reject { |k| k.start_with?("active-sessions-") }
  assert_equal 1, session_keys.length
  parsed = JSON.parse(storage.get(session_keys.first))
  assert_equal result[:token], parsed.fetch("session").fetch("token")
end

def test_secondary_storage_can_back_rate_limiting
  storage = BetterAuth::RedisStorage.new(client: FakeRedisClient.new)
  auth = BetterAuth.auth(
    base_url: "http://localhost:3000",
    secret: "redis-storage-secret-with-enough-entropy-12345",
    database: :memory,
    secondary_storage: storage,
    rate_limit: {storage: "secondary-storage", enabled: true, max: 1, window: 60}
  )

  3.times do
    auth.api.sign_in_email(body: {email: "rate@example.com", password: "x" * 12}, headers: {"x-forwarded-for" => "1.2.3.4"})
  rescue BetterAuth::APIError
    # expected after the first attempt
  end

  rate_limit_keys = storage.list_keys.select { |key| key.start_with?("rl-") || key.start_with?("rate-limit-") }
  refute_empty rate_limit_keys
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth-redis-storage && rbenv exec bundle exec ruby -Itest test/better_auth/redis_storage_test.rb -n /secondary_storage_can_back_/`

Expected: FAIL only if Better Auth core's storage key naming changes; otherwise PASS once the key prefix matches the runtime expectation. The test exists to lock the contract.

- [ ] **Step 3: Adjust the rate-limit prefix expectation if necessary**

If the test fails because the actual prefix is different (e.g. `rate-limit:` vs `rl-`), inspect `packages/better_auth/lib/better_auth/rate_limiter.rb` and update the assertion to match the production prefix exactly (do not change runtime behavior).

- [ ] **Step 4: Commit**

```bash
git add packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb
git commit -m "test(redis-storage): lock secondary-storage compatibility for sessions and rate limits"
```

### Task 7: Real Redis Integration Test Split

**Files:**
- Create: `packages/better_auth-redis-storage/test/better_auth/redis_storage_integration_test.rb`
- Modify: `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb` (delete the integration block)
- Modify: `packages/better_auth-redis-storage/test/test_helper.rb`
- Modify: `packages/better_auth-redis-storage/Rakefile`

- [ ] **Step 1: Move the existing real-Redis test into a new file**

Create `redis_storage_integration_test.rb` as a Minitest::Test that runs only when `ENV["REDIS_INTEGRATION"] == "1"`. Reuse the existing real-Redis assertions but split into:

```ruby
class RedisStorageIntegrationTest < Minitest::Test
  def setup
    skip unless ENV["REDIS_INTEGRATION"] == "1"

    redis_url = ENV["REDIS_URL"] || "redis://localhost:6379/15"
    require "redis"
    @client = Redis.new(url: redis_url)
    @client.ping
    @prefix_root = "better-auth-test:#{SecureRandom.hex(6)}"
    @storage = BetterAuth::RedisStorage.new(client: @client, key_prefix: "#{@prefix_root}:")
    @storage.clear
  rescue LoadError
    skip "redis gem is not available"
  rescue Redis::BaseConnectionError
    skip "Redis is not reachable at #{redis_url}"
  end

  def teardown
    @storage&.clear
    @client&.close if @client.respond_to?(:close)
  end

  def test_real_redis_round_trip_on_get_set_delete
    @storage.set("a", "one")
    @storage.set("b", "two", 60)
    assert_equal "one", @storage.get("a")
    assert_equal "two", @storage.get("b")

    @storage.delete("a")
    assert_nil @storage.get("a")
  end

  def test_real_redis_session_storage_with_store_session_in_database_false
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: @storage,
      session: {store_session_in_database: false}
    )
    result = auth.api.sign_up_email(body: {email: "redis-real@example.com", password: "password123", name: "Real User"})
    assert result[:token]

    keys = @storage.list_keys
    refute_empty keys
    session_key = keys.find { |key| !key.start_with?("active-sessions-") }
    parsed = JSON.parse(@storage.get(session_key))
    assert_equal result[:token], parsed.fetch("session").fetch("token")
  end

  def test_real_redis_rate_limiting_persists_under_secondary_storage
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: @storage,
      rate_limit: {storage: "secondary-storage", enabled: true, max: 1, window: 60}
    )

    auth.api.sign_in_email(body: {email: "rate@example.com", password: "x" * 12}, headers: {"x-forwarded-for" => "1.2.3.4"}) rescue nil
    auth.api.sign_in_email(body: {email: "rate@example.com", password: "x" * 12}, headers: {"x-forwarded-for" => "1.2.3.4"}) rescue nil

    refute_empty @storage.list_keys.select { |k| k != "active-sessions-" }
  end
end
```

- [ ] **Step 2: Delete the in-file integration block**

Remove `test_real_redis_stores_better_auth_sessions_with_prefix_isolation` from `redis_storage_test.rb`. Add a comment near the top of the unit test file pointing readers at the integration suite.

- [ ] **Step 3: Wire the Rake test loader**

Update `packages/better_auth-redis-storage/Rakefile` to load the new file and ensure `bundle exec rake test` runs both files. Also add a separate `rake test:integration` task that sets `REDIS_INTEGRATION=1` before invoking the integration suite.

- [ ] **Step 4: Run the integration tests with Redis available**

```bash
docker compose up -d redis
REDIS_INTEGRATION=1 REDIS_URL=redis://localhost:6379/15 \
  rbenv exec bundle exec ruby -Itest test/better_auth/redis_storage_integration_test.rb
```

Expected: PASS for all three integration tests.

- [ ] **Step 5: Confirm the unit suite runs without `REDIS_INTEGRATION`**

Run: `cd packages/better_auth-redis-storage && rbenv exec bundle exec rake test`

Expected: PASS, with the integration tests skipped when `REDIS_INTEGRATION` is unset.

- [ ] **Step 6: Commit**

```bash
git add packages/better_auth-redis-storage/test/better_auth/redis_storage_integration_test.rb \
        packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb \
        packages/better_auth-redis-storage/test/test_helper.rb \
        packages/better_auth-redis-storage/Rakefile
git commit -m "test(redis-storage): split real-Redis integration tests behind REDIS_INTEGRATION"
```

### Task 8: Documentation And Intentional Adaptations

**Files:**
- Modify: `packages/better_auth-redis-storage/README.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `packages/better_auth-redis-storage/CHANGELOG.md`

- [ ] Document the upstream-compatible call shape (`BetterAuth.redis_storage(client: redis)`) and that the canonical Ruby form is `BetterAuth::RedisStorage.new(client: redis)`.
- [ ] Document `key_prefix` semantics: defaults to `"better-auth:"`, `nil` falls back to the default, and any other value (including the empty string) is honored verbatim. Include the upstream-aligned warning that `key_prefix` is not isolated by Redis databases — applications with shared Redis instances must use distinct prefixes.
- [ ] Document the optional `scan_count:` constructor argument and recommended values (e.g. `100`-`1000` depending on database size) plus the guarantee that `KEYS` is the default.
- [ ] Document the `clear` empty-keys safety guard as a Ruby-only deviation from upstream.
- [ ] Document the `set(key, value, ttl)` TTL coercion table:
  - `nil`, non-numeric strings, `0`, negative numbers → `set` (no expiry).
  - Positive `Integer`, positive `Float` (truncated), positive numeric `String` → `setex(prefixed_key, ttl_int, value)`.
- [ ] Document that the gem returns `nil` (not `Promise<void>`) from `set`/`delete`/`clear`. Adopters should rely on `get` return values for assertions.
- [ ] Document the `SecondaryStorage` contract that any custom backend must implement (`get(key)`, `set(key, value, ttl = nil)`, `delete(key)`, optional `list_keys`/`clear`).
- [ ] Document that `@better-auth/redis-storage` is released as `1.6.x` upstream while `better_auth-redis-storage` versions independently. Pin the upstream parity tag (`v1.6.9`) in the README.
- [ ] Update `.docs/features/upstream-parity-matrix.md` to mark `redis-storage` as "100%" with the `1.6.9` upstream tag pinned and link this plan as the last verification entry.
- [ ] Add a CHANGELOG entry under `[Unreleased]` describing the new `scan_count` option, the module-level builder, and the integration test split. Do not bump the gem version unless a release is being prepared.

### Task 9: Final Verification

- [ ] Run `cd packages/better_auth-redis-storage && rbenv exec bundle exec rake test`.
- [ ] Run `docker compose up -d redis` and `REDIS_INTEGRATION=1 REDIS_URL=redis://localhost:6379/15 cd packages/better_auth-redis-storage && rbenv exec bundle exec rake test`.
- [ ] Run `cd packages/better_auth-redis-storage && RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb`.
- [ ] Run `cd packages/better_auth && rbenv exec bundle exec rake test` to confirm the broader Better Auth suite still passes when the gem is loaded as a secondary storage backend.
- [ ] Record exact run counts for every command above in this plan's Verification Log section before marking complete.

## Assumptions

- "100%" means **100% closure of upstream `@better-auth/redis-storage` server differences for the Ruby port**, plus explicit documentation for non-applicable client behavior (TypeScript-only typings) and intentional Ruby adaptations (`clear` empty-keys safety, optional `scan_count`).
- Adopters supply a Redis client that conforms to the `redis` gem's interface (`#get`, `#set`, `#setex`, `#del`, `#keys`, optionally `#scan`). Connection pooling is the application's responsibility.
- No version bumps or commits are part of this plan unless explicitly requested.

## Verification Log

- (fill in after each `rake test`, integration run, and `standardrb` run with run counts and elapsed time)
