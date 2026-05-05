# Redis Storage Audit And Fix Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix Redis storage TTL and scan-clear edge cases, make real Redis coverage run in CI/release verification, and record the upstream parity audit result.

**Architecture:** Keep the public Redis secondary-storage API unchanged and preserve upstream-compatible `KEYS` behavior by default. Apply Ruby-specific hardening only where the current adapter can produce invalid Redis commands or where `scan_count:` already opts into a safer operational path.

**Tech Stack:** Ruby 3.2+, Minitest, StandardRB, `redis` gem, GitHub Actions, Better Auth upstream `@better-auth/redis-storage` v1.6.9.

---

## Findings

- [x] Upstream `@better-auth/redis-storage` v1.6.9 is intentionally small: `get`, `set`, `delete`, `listKeys`, and `clear` with `ioredis`, default `keyPrefix: "better-auth:"`, `KEYS` listing, and `SETEX` for positive TTLs.
- [x] Ruby already covers the upstream surface plus intentional adaptations: snake_case aliases, module/class builders, `nil` key rejection, `nil` prefix defaulting, optional `scan_count:`, empty-clear guard, and chunked `DEL`.
- [x] Current Ruby TTL coercion can convert positive sub-second numerics to `0` and call `SETEX key 0 value`, which real Redis rejects.
- [x] Current `clear` with `scan_count:` still materializes all matching keys through `storage_keys`, so it does not fully realize the operational benefit of SCAN for large keyspaces.
- [x] Redis CI starts a Redis service but only runs `bundle exec rake test`, so the real Redis suite remains skipped unless `REDIS_INTEGRATION=1` and `test:integration` are invoked explicitly.

## Implementation Checklist

- [x] Add failing unit tests for sub-second TTLs in `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb`.
- [x] Update `coerce_ttl` to return `nil` unless the final integer TTL is at least `1`.
- [x] Add a unit test proving `clear` with `scan_count:` deletes in chunks without calling `keys`.
- [x] Refactor `clear` to stream `SCAN` batches when `scan_count:` is set.
- [x] Add `atomic_clear:` as a Ruby-only opt-in for generation-scoped keys and logically atomic clears under concurrent writers.
- [x] Add unit and real Redis coverage for `atomic_clear:`.
- [x] Run `rbenv exec bundle exec rake test` in `packages/better_auth-redis-storage`.
- [x] Run `rbenv exec bundle exec standardrb` in `packages/better_auth-redis-storage`.
- [x] Run `REDIS_INTEGRATION=1 REDIS_URL=redis://localhost:6379/15 rbenv exec bundle exec rake test:integration` when Redis is available.
- [x] Update `.github/workflows/ci.yml` to run Redis integration explicitly.
- [x] Update `.github/workflows/release.yml` to run Redis integration explicitly.
- [x] Update `packages/better_auth-redis-storage/CHANGELOG.md`.
- [x] Update `.docs/features/upstream-parity-matrix.md` to reference this plan.

## Public API

- [x] Existing public API remains compatible: `BetterAuth.redis_storage`, `BetterAuth::RedisStorage.new`, `key_prefix:`, `scan_count:`, `list_keys`, `listKeys`, and `clear` still work.
- [x] New opt-in public option: `atomic_clear: true`, supported by `BetterAuth.redis_storage`, `BetterAuth::RedisStorage.new`, `BetterAuth::RedisStorage.build`, and `BetterAuth::RedisStorage.redisStorage`.
- [x] The only behavior change is for invalid real Redis calls: sub-second numeric TTLs fall back to plain `SET` instead of attempting `SETEX 0`.
- [x] With `atomic_clear: true`, Redis data keys include a generation segment such as `better-auth:v1:<logical-key>`, and `clear` advances the generation with `INCR`.

## Test Plan

- [x] Unit: `rbenv exec bundle exec rake test`
- [x] Style: `rbenv exec bundle exec standardrb`
- [x] Real Redis: `REDIS_INTEGRATION=1 REDIS_URL=redis://localhost:6379/15 rbenv exec bundle exec rake test:integration`
- [x] CI acceptance: Redis package workflow shows unit tests, StandardRB, and real Redis integration as executed, not skipped.
