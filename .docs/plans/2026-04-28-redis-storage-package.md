# Redis Storage Package

**Goal:** Add a Ruby package equivalent to upstream `@better-auth/redis-storage` so apps can use Redis as `secondary_storage` without adding Redis dependencies to `better_auth` core.

**Upstream reference:** `upstream/packages/redis-storage/src/redis-storage.ts`, `upstream/packages/redis-storage/README.md`, and the existing secondary-storage integration in `upstream/packages/better-auth/src/db/internal-adapter.ts`.

## Findings

- [x] Upstream ships Redis storage as a separate package because it is an optional secondary-storage adapter with its own Redis client peer dependency.
- [x] Ruby core already supports the secondary-storage contract for sessions, active-session indexes, and rate limiting.
- [x] Ruby does not yet have a first-party Redis secondary-storage adapter.

## Implementation

- [x] Use the package name `better_auth-redis-storage`, require path `better_auth/redis_storage`, and namespace `BetterAuth::RedisStorage`.
- [x] Add a package-owned Redis dependency instead of adding Redis to `better_auth` core.
- [x] Implement `get`, `set`, `delete`, `list_keys`, and `clear` with a configurable `key_prefix` defaulting to `better-auth:`.
- [x] Keep compatibility with Redis-like clients that expose `get`, `set`, `setex`, `del`, and `keys`.
- [x] Document usage through `secondary_storage: BetterAuth::RedisStorage.new(client: redis)`.

## Verification

- [x] Run Redis storage package tests.
- [x] Run StandardRB for the new package.
- [ ] Update this plan with any Ruby-specific adaptation discovered during implementation.
