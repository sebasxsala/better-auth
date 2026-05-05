# Changelog

## Unreleased

- Validate `scan_count` as either `nil` or a positive `Integer`.
- Reject `nil` logical keys before prefixing Redis keys.
- Coerce positive finite non-Integer `Numeric` TTL values for `SETEX`.
- Delete `clear` matches in chunks to avoid oversized Redis `DEL` commands.
- Document Redis operational caveats for empty prefixes, key ordering, TTLs, and clusters.

## 0.2.0 - 2026-04-29

- Add `BetterAuth.redis_storage` and `BetterAuth::RedisStorage.redisStorage` builders for upstream-shaped Redis storage configuration.
- Add optional `scan_count:` support to use Redis `SCAN` instead of upstream-compatible `KEYS`.
- Split real Redis coverage into a `REDIS_INTEGRATION=1` integration suite and expand secondary-storage compatibility tests.

## 0.1.0

- Initial Redis secondary storage package for Better Auth Ruby.
