# Feature: API Key Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/api-key/src/index.ts`, `upstream/packages/api-key/src/schema.ts`, `upstream/packages/api-key/src/adapter.ts`, `upstream/packages/api-key/src/rate-limit.ts`, `upstream/packages/api-key/src/routes/*.ts`, `upstream/packages/api-key/src/api-key.test.ts`, `upstream/packages/api-key/src/org-api-key.test.ts`

## Summary

Adds API key creation, verification, management, quotas, metadata, permissions, storage modes, multi-configuration support, organization-owned keys, and optional API-key-backed sessions.

## Ruby Adaptation

- External package: install `better_auth-api-key` and `require "better_auth/api_key"`.
- Exposed as `BetterAuth::Plugins.api_key`; core `better_auth` keeps only a compatibility shim.
- Adds `/api-key/create`, `/api-key/verify`, `/api-key/get`, `/api-key/update`, `/api-key/delete`, `/api-key/list`, and `/api-key/delete-all-expired-api-keys`.
- Adds `apikey` schema with upstream fields for key identity, ownership, expiration, rate limits, remaining usage, refill settings, permissions, metadata, and timestamps.
- Supports upstream `configId` and `referenceId`, while continuing to read legacy `userId` records.
- Supports multiple API key configurations, `default_prefix`, and `references: "user"` or `"organization"`.
- `/api-key/verify` returns upstream-style `{ valid, error, key }` payloads for verification failures.
- `/api-key/list` returns upstream-style `{ apiKeys, total, limit, offset }` and supports config filtering, pagination, sorting, and organization filtering.
- Uses SHA-256/base64url key hashing by default, with `disable_key_hashing` support.
- Supports database storage and secondary-storage with database fallback. In fallback mode, secondary-storage reference lists are invalidated on writes/deletes so database-backed listing remains the source of truth and concurrent writers cannot lose key IDs through read-modify-write races.
- Supports deferred usage updates through `advanced.background_tasks.handler`.
- Migrates legacy double-stringified metadata while returning metadata as Ruby hashes.
- `enable_session_for_api_keys` injects an API-key session so `/get-session` works with configured API key headers.

## Testing

```bash
cd packages/better_auth-api-key
rbenv exec bundle exec ruby -Itest test/better_auth/api_key_test.rb
```
