# Feature: API Key Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/api-key/index.ts`, `upstream/packages/better-auth/src/plugins/api-key/schema.ts`, `upstream/packages/better-auth/src/plugins/api-key/adapter.ts`, `upstream/packages/better-auth/src/plugins/api-key/rate-limit.ts`, `upstream/packages/better-auth/src/plugins/api-key/routes/*.ts`, `upstream/packages/better-auth/src/plugins/api-key/api-key.test.ts`

## Summary

Adds API key creation, verification, management, quotas, metadata, permissions, storage modes, and optional API-key-backed sessions.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.api_key`.
- Adds `/api-key/create`, `/api-key/verify`, `/api-key/get`, `/api-key/update`, `/api-key/delete`, `/api-key/list`, and `/api-key/delete-all-expired-api-keys`.
- Adds `apikey` schema with upstream fields for key identity, ownership, expiration, rate limits, remaining usage, refill settings, permissions, metadata, and timestamps.
- Uses SHA-256/base64url key hashing by default, with `disable_key_hashing` support.
- Supports database storage and secondary-storage with database fallback.
- Supports deferred usage updates through `advanced.background_tasks.handler`.
- Migrates legacy double-stringified metadata while returning metadata as Ruby hashes.
- `enable_session_for_api_keys` injects an API-key session so `/get-session` works with configured API key headers.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/api_key_test.rb
```
