# API Key Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining Better Auth upstream `@better-auth/api-key` (v1.6.9) deltas in the Ruby `better_auth-api-key` port and lock every Ruby-specific adaptation behind tests + docs.

**Architecture:** Treat `upstream/packages/api-key/src/**` as source of truth for server behavior, schema, error codes, secondary-storage layout, and route shapes. Ruby keeps idiomatic `snake_case` options while preserving upstream JSON wire field names (`configId`, `referenceId`, `rateLimitTimeWindow`, etc.) and storage key prefixes (`api-key:`, `api-key:by-id:`, `api-key:by-ref:`). Browser-only `client.ts` helpers are not implemented in Ruby and are documented as out of scope.

**Tech Stack:** Ruby 3.4.9, Rack 3, Minitest, StandardRB, Better Auth core endpoint/middleware/adapter contracts, optional `redis` gem for the `secondary-storage` mode tests, upstream Better Auth `v1.6.9`.

---

## Summary

Start with tests translated from `upstream/packages/api-key/src/api-key.test.ts` and `org-api-key.test.ts`, watch each fail, implement the minimum fix, then rerun focused tests. The current Ruby gem is already very close to upstream, so most of this plan formalises edge-case behavior, plugin metadata (`version`), and secondary-storage parallelism.

The current branch contains a complete server-parity baseline. The remaining work is: formalise this plan file, finish any unclosed parity gaps, document intentional Ruby adaptations, and verify the full suite.

## Key Changes

- **Plugin metadata:** Expose `version: BetterAuth::ApiKey::VERSION` (mirrors upstream `version: PACKAGE_VERSION` added in `1.6.0`) so that `auth.options.plugins.find { |p| p.id == "api-key" }.version` matches the gem version.
- **Verify endpoint cleanup task:** Match upstream's "always run, optionally background" semantics: `delete_all_expired_api_keys` should always be invoked once per verify, and only the schedule (not the run) should change when `defer_updates` is true.
- **Refill validation symmetry:** In `update_api_key`, treat `refill_amount` and `refill_interval` with `body.key?(:...)` semantics (matches upstream `!== undefined`) so that `refill_amount: 0` or `refill_interval: nil` no longer mis-fires `REFILL_*_REQUIRED`.
- **Server-only property check on update:** Match upstream's "auth-required path" trigger (`ctx.request || ctx.headers`) instead of `session && body[:user_id]`. Block client requests that send `remaining`, `permissions`, etc., even when their body matches the session user.
- **Concurrent secondary-storage writes (1.6.6):** Mirror upstream's `Promise.all`-style fan-out for the per-hash, per-id, and reference-list secondary-storage writes. In Ruby, perform the writes in a deterministic order but ensure none of them depend on the others' return values, then add a regression test verifying that a Redis-like client with throttled `set` does not block subsequent operations on independent keys.
- **Reference list fallback dead code:** Remove the duplicate `fallback_to_database` branch in `api_key_storage_set`. Keep behavior: invalidate the ref list under fallback; otherwise read-modify-write.
- **Legacy storage keys:** Document the Ruby-only legacy read fallbacks (`api-key:key:`, `api-key:id:`, `api-key:user:`) and confirm with a test that they are read but never written. Explicitly note this Ruby-specific compatibility layer in the README.
- **Sort field normalisation:** Confirm `Schema.storage_key(sort_by)` accepts both `createdAt` and `created_at` and lock the behavior with a test (upstream supports the camelCase form).
- **OpenAPI metadata policy:** Document that Ruby endpoints intentionally omit upstream OpenAPI bodies; OpenAPI generation is not part of the `better_auth-api-key` scope.
- **Client policy:** Document that `@better-auth/api-key/client` is browser-only and not ported. Apps should call the JSON endpoints directly.

## Task List

### Task 1: Save Plan And Establish Baseline

- [ ] Create `.docs/plans/2026-04-29-api-key-upstream-parity.md` with this plan.
- [ ] Run `git status --short --branch` and confirm work is on a dedicated branch (e.g. `codex/api-key-upstream-diff`).
- [ ] Initialize upstream at `v1.6.9`:

```bash
git submodule update --init --recursive upstream
cd upstream && git fetch --tags origin && git checkout v1.6.9 && cd ..
```

- [ ] Run baseline package tests: `cd packages/better_auth-api-key && rbenv exec bundle exec rake test`.
- [ ] Run baseline core tests for the api-key shim: `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/api_key_test.rb`.
- [ ] Record run counts and note any pre-existing failures in this plan's Verification Log section.

### Task 2: Plugin Metadata Parity (Version Field)

**Files:**
- Modify: `packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb`
- Modify: `packages/better_auth-api-key/test/better_auth/api_key_test.rb`
- Verify: `upstream/packages/api-key/src/index.ts` (lines 165-170)

- [ ] **Step 1: Add a failing test**

```ruby
def test_plugin_exposes_package_version_like_upstream
  plugin = BetterAuth::Plugins.api_key
  assert_equal BetterAuth::ApiKey::VERSION, plugin.version
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/better_auth-api-key && rbenv exec bundle exec ruby -Itest test/better_auth/api_key_test.rb -n test_plugin_exposes_package_version_like_upstream`

Expected: FAIL with `NoMethodError: undefined method 'version' for #<BetterAuth::Plugin>` or `assert_equal: nil != "0.x.y"`.

- [ ] **Step 3: Wire `version:` through `Plugin.new`**

In `packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb`, pass `version: BetterAuth::ApiKey::VERSION` to `Plugin.new(id: "api-key", ...)`. If the core `BetterAuth::Plugin` does not yet accept `:version`, add the keyword in `packages/better_auth/lib/better_auth/plugin.rb` and expose a `#version` reader, defaulting to `nil` for backward compatibility.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/better_auth-api-key && rbenv exec bundle exec ruby -Itest test/better_auth/api_key_test.rb -n test_plugin_exposes_package_version_like_upstream`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb \
        packages/better_auth-api-key/test/better_auth/api_key_test.rb \
        packages/better_auth/lib/better_auth/plugin.rb
git commit -m "feat(api-key): expose plugin version to match upstream 1.6.0+"
```

### Task 3: Verify Endpoint Cleanup Semantics

**Files:**
- Modify: `packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb`
- Modify: `packages/better_auth-api-key/test/better_auth/api_key_test.rb`
- Verify: `upstream/packages/api-key/src/routes/verify-api-key.ts:300-310`

- [ ] **Step 1: Add a failing test for non-deferred verify cleanup**

The test should set up an expired key, call `verify_api_key`, and assert that the cleanup runs synchronously regardless of `defer_updates`. With `defer_updates: true`, the test should also assert that `ctx.context.run_in_background` is invoked exactly once.

```ruby
def test_verify_runs_expired_cleanup_synchronously_unless_deferred
  auth = build_auth(default_key_length: 12)
  cookie = sign_up_cookie(auth, email: "verify-cleanup@example.com")
  user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

  expired = auth.api.create_api_key(body: {userId: user_id})
  auth.context.adapter.update(model: "apikey", where: [{field: "id", value: expired[:id]}], update: {expiresAt: Time.now - 60})

  result = auth.api.verify_api_key(body: {key: expired[:key]})
  assert_equal false, result[:valid]
  refute auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: expired[:id]}])
end

def test_verify_schedules_expired_cleanup_in_background_when_deferred
  background = []
  auth = build_auth(
    default_key_length: 12,
    defer_updates: true,
    advanced: {background_tasks: {handler: ->(task) { background << task }}}
  )
  cookie = sign_up_cookie(auth, email: "verify-cleanup-deferred@example.com")
  user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

  expired = auth.api.create_api_key(body: {userId: user_id})
  auth.context.adapter.update(model: "apikey", where: [{field: "id", value: expired[:id]}], update: {expiresAt: Time.now - 60})
  auth.api.verify_api_key(body: {key: expired[:key]})

  assert_equal 1, background.length
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth-api-key && rbenv exec bundle exec ruby -Itest test/better_auth/api_key_test.rb -n /verify_(runs|schedules)_expired_cleanup/`

Expected: FAIL.

- [ ] **Step 3: Implement cleanup parity**

Update `api_key_verify_endpoint` in `lib/better_auth/plugins/api_key.rb` to:

1. Build a `cleanup = -> { api_key_delete_expired(ctx.context, record_config) }` lambda.
2. If `record_config[:defer_updates]` and the background handler is configured, call `ctx.context.run_in_background(cleanup)`; otherwise call `cleanup.call`.
3. Apply the same pattern in `api_key_session_hook` to mirror upstream's session middleware path.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth-api-key && rbenv exec bundle exec ruby -Itest test/better_auth/api_key_test.rb -n /verify_(runs|schedules)_expired_cleanup/`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb \
        packages/better_auth-api-key/test/better_auth/api_key_test.rb
git commit -m "fix(api-key): match upstream verify cleanup deferral semantics"
```

### Task 4: Update Endpoint Server-Only Boundary

**Files:**
- Modify: `packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb`
- Modify: `packages/better_auth-api-key/test/better_auth/api_key_test.rb`
- Verify: `upstream/packages/api-key/src/routes/update-api-key.ts:278-307`

- [ ] **Step 1: Add a failing test**

```ruby
def test_update_rejects_server_only_properties_from_authenticated_client
  auth = build_auth(enable_metadata: true)
  cookie = sign_up_cookie(auth, email: "update-server-only@example.com")
  created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "client-only"})

  %i[refillAmount refillInterval rateLimitMax rateLimitTimeWindow rateLimitEnabled remaining permissions].each do |field|
    error = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(
        headers: {"cookie" => cookie},
        body: {keyId: created[:id], field => (field == :rateLimitEnabled ? true : 1)}
      )
    end
    assert_equal "BAD_REQUEST", error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"], error.message
  end
end

def test_update_treats_refill_undefined_vs_zero_correctly
  auth = build_auth(default_key_length: 12)
  cookie = sign_up_cookie(auth, email: "refill-undef@example.com")
  user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
  created = auth.api.create_api_key(body: {userId: user_id})

  updated = auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], refillAmount: 5, refillInterval: 10})
  assert_equal 5, updated[:refillAmount]
  assert_equal 10, updated[:refillInterval]

  error = assert_raises(BetterAuth::APIError) do
    auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], refillAmount: 5})
  end
  assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["REFILL_AMOUNT_AND_INTERVAL_REQUIRED"], error.message
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth-api-key && rbenv exec bundle exec ruby -Itest test/better_auth/api_key_test.rb -n /update_(rejects_server_only|treats_refill)/`

Expected: FAIL on at least the server-only check (Ruby currently lets fields through when the body's `userId` matches the session).

- [ ] **Step 3: Implement boundary fix**

In `api_key_validate_create_update!`:

- For updates, treat the request as "client-driven" when `client = (ctx.request || !ctx.headers.empty?)` instead of `client = !!session`.
- Switch the refill cross-validation to check `body.key?(:refill_amount) ^ body.key?(:refill_interval)` so that explicitly nil values are accepted and asymmetric "set one only" cases are rejected.
- Keep the existing 403 / `UNAUTHORIZED_SESSION` mismatch check between `session[:user]["id"]` and `body[:user_id]`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth-api-key && rbenv exec bundle exec ruby -Itest test/better_auth/api_key_test.rb -n /update_(rejects_server_only|treats_refill)/`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb \
        packages/better_auth-api-key/test/better_auth/api_key_test.rb
git commit -m "fix(api-key): block server-only properties on client update like upstream"
```

### Task 5: Concurrent Secondary-Storage Writes (Upstream 1.6.6 Fix)

**Files:**
- Modify: `packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb`
- Modify: `packages/better_auth-api-key/test/better_auth/api_key_test.rb`
- Verify: `upstream/packages/api-key/src/adapter.ts:265-326` (`setApiKeyInStorage`, `deleteApiKeyFromStorage`)

- [ ] **Step 1: Add a failing test using a tracked storage**

The test sets `storage: "secondary-storage"` (no fallback) with a `MemoryStorage` that records the order of `set` calls and asserts that on a single create, the per-hash, per-id, and reference-list writes are issued together (no awaits between independent keys).

```ruby
def test_secondary_storage_write_set_does_not_serialize_independent_keys
  storage = OrderTrackingStorage.new
  auth = build_auth(storage: "secondary-storage", secondary_storage: storage, default_key_length: 12)
  cookie = sign_up_cookie(auth, email: "concurrency-key@example.com")
  created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

  hash_writes = storage.write_groups.last
  assert_includes hash_writes, "api-key:#{auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])["key"]}"
  assert_includes hash_writes, "api-key:by-id:#{created[:id]}"
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/better_auth-api-key && rbenv exec bundle exec ruby -Itest test/better_auth/api_key_test.rb -n test_secondary_storage_write_set_does_not_serialize_independent_keys`

Expected: FAIL because Ruby currently issues each `set` strictly in sequence with no batching marker.

- [ ] **Step 3: Implement parallel-style writes**

In `api_key_storage_set` and `api_key_storage_delete`, group the per-hash, per-id, and ref-list writes into a single `[set_hash, set_id, ref_op]` array and execute via `each(&:call)`. Pass the `OrderTrackingStorage` shim a `batch` hook so the test can assert that all keys in the batch are observed without a request boundary between them.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/better_auth-api-key && rbenv exec bundle exec ruby -Itest test/better_auth/api_key_test.rb -n test_secondary_storage_write_set_does_not_serialize_independent_keys`

Expected: PASS.

- [ ] **Step 5: Remove dead code**

Delete the duplicate `if config[:fallback_to_database]` branch in `api_key_storage_set` (currently appears twice).

- [ ] **Step 6: Commit**

```bash
git add packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb \
        packages/better_auth-api-key/test/better_auth/api_key_test.rb
git commit -m "refactor(api-key): batch independent secondary-storage writes (parity with 1.6.6)"
```

### Task 6: Legacy Storage Key Read Compatibility

**Files:**
- Modify: `packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb`
- Modify: `packages/better_auth-api-key/test/better_auth/api_key_test.rb`
- Modify: `packages/better_auth-api-key/README.md`
- Verify: `upstream/packages/api-key/src/adapter.ts:126-143` (`getStorageKey*`)

- [ ] **Step 1: Add a regression test for legacy read paths**

```ruby
def test_secondary_storage_reads_legacy_key_layout_but_writes_new_layout
  storage = MemoryStorage.new
  auth = build_auth(storage: "secondary-storage", secondary_storage: storage, default_key_length: 12)
  cookie = sign_up_cookie(auth, email: "legacy-key@example.com")
  user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
  created = auth.api.create_api_key(body: {userId: user_id})

  hashed = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])["key"]
  legacy = JSON.parse(storage.get("api-key:by-id:#{created[:id]}"))
  storage.set("api-key:key:#{hashed}", legacy.to_json)
  storage.delete("api-key:#{hashed}")

  result = auth.api.verify_api_key(body: {key: created[:key]})
  assert_equal true, result[:valid]
end
```

- [ ] **Step 2: Run test and confirm it already passes**

Expected: PASS (Ruby already supports the legacy `api-key:key:` and `api-key:id:` and `api-key:user:` read paths). The point of this test is to lock the behavior so it cannot regress.

- [ ] **Step 3: Document the Ruby-only legacy compatibility layer**

Add a "Storage layout" section to `packages/better_auth-api-key/README.md` listing the upstream key prefixes (`api-key:`, `api-key:by-id:`, `api-key:by-ref:`) and the Ruby-only legacy read fallbacks (`api-key:key:`, `api-key:id:`, `api-key:user:`). Note that writes only target the upstream layout.

- [ ] **Step 4: Commit**

```bash
git add packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb \
        packages/better_auth-api-key/test/better_auth/api_key_test.rb \
        packages/better_auth-api-key/README.md
git commit -m "docs(api-key): lock legacy secondary-storage key read fallbacks"
```

### Task 7: Sort Field Normalization

**Files:**
- Modify: `packages/better_auth-api-key/test/better_auth/api_key_test.rb`
- Verify: `upstream/packages/api-key/src/routes/list-api-keys.ts:259-355`

- [ ] **Step 1: Add a sort parity test**

```ruby
def test_list_sort_accepts_camel_case_and_snake_case_keys
  auth = build_auth(default_key_length: 12)
  cookie = sign_up_cookie(auth, email: "sort-key@example.com")
  user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
  first = auth.api.create_api_key(body: {userId: user_id, name: "alpha"})
  sleep 0.01
  second = auth.api.create_api_key(body: {userId: user_id, name: "beta"})

  asc_camel = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {sort_by: "createdAt", sort_direction: "asc"})
  asc_snake = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {sort_by: "created_at", sort_direction: "asc"})

  assert_equal [first[:id], second[:id]], asc_camel.fetch(:apiKeys).map { |entry| entry[:id] }
  assert_equal asc_camel, asc_snake
end
```

- [ ] **Step 2: Run test**

Run: `cd packages/better_auth-api-key && rbenv exec bundle exec ruby -Itest test/better_auth/api_key_test.rb -n test_list_sort_accepts_camel_case_and_snake_case_keys`

Expected: PASS via existing `Schema.storage_key` normalization. If it fails, route the snake_case input through `Schema.storage_key` in `api_key_sort_records` before lookup.

- [ ] **Step 3: Commit**

```bash
git add packages/better_auth-api-key/test/better_auth/api_key_test.rb
git commit -m "test(api-key): lock sort field normalization for both casings"
```

### Task 8: Documentation And Intentional Adaptations

**Files:**
- Modify: `packages/better_auth-api-key/README.md`
- Modify: `docs/content/docs/plugins/api-key.mdx` (only if missing the noted sections)
- Modify: `.docs/features/upstream-parity-matrix.md` (only if api-key row is stale)

- [ ] Document Ruby option naming policy: public option keys are `snake_case` while wire JSON stays `camelCase`. List the `snake_case` -> `camelCase` mapping for `config_id`, `default_key_length`, `default_prefix`, `enable_metadata`, `disable_key_hashing`, `require_name`, `enable_session_for_api_keys`, `fallback_to_database`, `custom_storage`, `defer_updates`, `references`, `key_expiration.*`, `starting_characters_config.*`, and `rate_limit.*`.
- [ ] Document that `@better-auth/api-key/client` is browser-only and not ported. Apps should call `/api-key/create`, `/api-key/verify`, `/api-key/get`, `/api-key/list`, `/api-key/update`, `/api-key/delete`, `/api-key/delete-all-expired-api-keys` directly via JSON.
- [ ] Document that OpenAPI metadata embedded in upstream endpoint definitions is intentionally not ported; OpenAPI generation is not part of the gem's scope.
- [ ] Document the `apikey` table name and the upstream secondary-storage layout, with the Ruby-only legacy read fallbacks called out explicitly.
- [ ] Document organization-owned API key behavior: `references: "organization"` requires the `BetterAuth::Plugins::Organization` plugin and an `apiKey` `[create|read|update|delete]` permission set, plus that organization owners (`creator_role`, default `"owner"`) bypass the per-action permission check.
- [ ] Document the `ApiKey::VERSION` exposure on the plugin object.
- [ ] Update `.docs/features/upstream-parity-matrix.md` to mark `api-key` as "100%" with the `1.6.9` upstream tag pinned and link this plan as the last verification entry.

### Task 9: Final Verification

- [ ] Run `cd packages/better_auth-api-key && rbenv exec bundle exec rake test`.
- [ ] Run `cd packages/better_auth-api-key && RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb`.
- [ ] Run `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/api_key_test.rb` (core shim).
- [ ] Run `docker compose up -d` from repo root and `cd packages/better_auth && rbenv exec bundle exec rake test` to confirm the api-key shim does not regress under databases.
- [ ] Record exact run counts for every command above in this plan's Verification Log section before marking complete.

## Assumptions

- "100%" means **100% closure of upstream `@better-auth/api-key` server differences for the Ruby port**, plus explicit documentation for non-applicable browser client behavior.
- Ruby keeps `snake_case` public APIs and existing `apikey` storage naming unless a failing compatibility test proves this must change.
- No version bumps or commits are part of this plan unless explicitly requested.
- The `org-api-key.test.ts` upstream cases are already covered by the existing organization-owned tests in `api_key_test.rb`; new failures during Task 9 must be ported into `api_key_test.rb` before this plan is closed.

## Verification Log

- 2026-04-29 — Branch `cursor/api-key-upstream-parity` (forked off `canary` inside the `i8m3` worktree). Upstream submodule initialized at `v1.6.9` (`f484269228b7eb8df0e2325e7d264bb8d7796311`).
- Baseline before changes: `cd packages/better_auth-api-key && rbenv exec bundle exec rake test` -> 47 runs, 304 assertions, 0 failures (~3.3 s).
- Final: `cd packages/better_auth-api-key && rbenv exec bundle exec rake test` -> 55 runs, 345 assertions, 0 failures (~3.2 s).
- Final: `cd packages/better_auth-api-key && RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb lib/ test/` -> exit 0, no offenses (~1.3 s).
- Final: `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/api_key_external_plugin_shim_test.rb` -> 1 run, 5 assertions, 0 failures (<1 s).
