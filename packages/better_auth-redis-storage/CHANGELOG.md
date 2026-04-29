# Changelog

## Unreleased

## 0.2.0 - 2026-04-29

- Add `BetterAuth.redis_storage` and `BetterAuth::RedisStorage.redisStorage` builders for upstream-shaped Redis storage configuration.
- Add optional `scan_count:` support to use Redis `SCAN` instead of upstream-compatible `KEYS`.
- Split real Redis coverage into a `REDIS_INTEGRATION=1` integration suite and expand secondary-storage compatibility tests.

## 0.1.0

- Initial Redis secondary storage package for Better Auth Ruby.
