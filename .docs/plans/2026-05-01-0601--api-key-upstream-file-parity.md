# API Key Upstream File Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the Ruby API key package toward Better Auth upstream `packages/api-key` parity by matching upstream structure and tests nearly file-by-file, while verifying the already-ported behavior did not miss edge cases.

**Architecture:** Keep `BetterAuth::Plugins.api_key` as the public Ruby plugin entrypoint, but split the current monolithic `packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb` into focused Ruby modules that mirror upstream boundaries: configuration/plugin setup, routes, adapter/storage, rate limit, schema, organization authorization, errors, utils, and types. Preserve existing public endpoint names and Ruby-compatible snake_case/camelCase input normalization while treating upstream `v1.6.9` as the behavioral source of truth.

**Tech Stack:** Ruby 3.2+, Minitest, `better_auth`, `better_auth-api-key`, upstream Better Auth `v1.6.9` TypeScript source under `upstream/packages/api-key/src`.

---

## Scope

- [x] Use `upstream/packages/api-key/src` at Better Auth `v1.6.9` as source of truth.
- [x] Preserve public Ruby plugin entrypoint `BetterAuth::Plugins.api_key`.
- [x] Preserve public loader `require "better_auth/api_key"`.
- [x] Preserve endpoint paths: `/api-key/create`, `/api-key/verify`, `/api-key/get`, `/api-key/update`, `/api-key/delete`, `/api-key/list`, `/api-key/delete-all-expired-api-keys`.
- [x] Preserve Ruby support for snake_case and camelCase request keys where it already exists.
- [x] Preserve current database table/model name `apikey`.
- [x] Split structure without changing behavior first.
- [x] Port/audit upstream tests behavior-by-behavior after structure exists.
- [x] Keep legacy compatibility behaviors that already exist, including old secondary-storage key layouts and metadata migration, and document them as Ruby compatibility additions when they exceed upstream.
- [x] Do not bump gem versions unless this work is explicitly released.

## Current Ruby State

- [x] Package exists at `packages/better_auth-api-key`.
- [x] Public loader exists: `packages/better_auth-api-key/lib/better_auth/api_key.rb`.
- [x] Version file exists: `packages/better_auth-api-key/lib/better_auth/api_key/version.rb`.
- [x] Main plugin exists: `packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb`.
- [x] Current behavior tests exist in one large file: `packages/better_auth-api-key/test/better_auth/api_key_test.rb`.
- [x] Initial upstream-like module files now exist.
- [x] Initial mirrored test files now exist.
- [x] Endpoint factory methods now live in route modules and `plugins/api_key.rb` delegates to them.
- [x] Organization authorization now lives in `api_key/org_authorization.rb`.
- [x] Config resolution/configId matching/expired cleanup now live in `api_key/routes/index.rb`.
- [x] Secondary-storage helpers, reference-list helpers, serialization/deserialization, and storage key layout now live in `api_key/adapter.rb`.
- [x] Database CRUD orchestration and metadata migration now live in `api_key/adapter.rb`.
- [x] Create/update validation, permission checks, and update payload building now live in `api_key/validation.rb`.
- [x] Record id/config/reference helpers now live in `api_key/types.rb`.
- [x] Public API key response shaping now lives in `api_key/utils.rb`.
- [x] Plugin configuration normalization now lives in `api_key/configuration.rb`.
- [x] Key generation, hashing, body normalization, expiration calculation, and header lookup now live in `api_key/keys.rb`.
- [x] API-key session hook orchestration now lives in `api_key/session.rb`.
- [x] API-key validation and usage update orchestration now live in `api_key/validation.rb`.
- [x] List sorting/query validation and error payload helpers now live in `api_key/utils.rb`.
- [x] Create reference resolution now lives in `api_key/org_authorization.rb`.
- [x] Delete/cleanup scheduling now lives in adapter/routes modules.
- [x] Background-task and request-auth checks now live in `api_key/utils.rb`.
- [x] `plugins/api_key.rb` now primarily contains plugin assembly plus compatibility delegators.
- [x] Most exhaustive upstream behavior coverage still lives in the monolithic Minitest file, but full upstream checklist classification now has coverage references or intentional-difference notes.

## Inventory Snapshot

- [x] Upstream `upstream/packages/api-key/src/api-key.test.ts` has 166 `it(...)` cases.
- [x] Upstream `upstream/packages/api-key/src/org-api-key.test.ts` has 10 `it(...)` cases.
- [x] Ruby API key package currently has 174 Minitest cases: 101 in `test/better_auth/api_key_test.rb` and 73 in mirrored module/route test files.
- [x] `packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb` is down to 314 lines after extraction and now delegates to `BetterAuth::APIKey` modules for behavior.
- [x] Latest package verification after extraction: `rbenv exec bundle exec rake test` => 174 runs, 819 assertions, 0 failures, 0 errors, 0 skips.
- [x] Latest package style verification after extraction: `rbenv exec bundle exec standardrb` => clean.

## Upstream Source Checklist

### Package Entrypoints

- [x] Port/audit structure for `upstream/packages/api-key/src/index.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/client.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/version.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/error-codes.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/types.ts`.

### Schema and Utilities

- [x] Port/audit structure for `upstream/packages/api-key/src/schema.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/utils.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/rate-limit.ts`.

### Adapter and Storage

- [x] Port/audit structure for `upstream/packages/api-key/src/adapter.ts`.
- [x] Port/audit `parseDoubleStringifiedMetadata`.
- [x] Port/audit `batchMigrateLegacyMetadata`.
- [x] Port/audit `migrateDoubleStringifiedMetadata`.
- [x] Port/audit storage key builders for hash, id, and reference list.
- [x] Port/audit storage serialization and deserialization.
- [x] Port/audit TTL calculation from `expiresAt`.
- [x] Port/audit secondary-storage reads by hashed key and id.
- [x] Port/audit reference-list mutation semantics.
- [x] Port/audit `getApiKey`.
- [x] Port/audit `getApiKeyById`.
- [x] Port/audit `setApiKey`.
- [x] Port/audit `deleteApiKey`.
- [x] Port/audit `listApiKeys`.
- [x] Port/audit fallback-to-database warming and write-through behavior.
- [x] Port/audit parallel storage population behavior where Ruby storage API supports it. Ruby secondary storage is synchronous; no `Promise`/`mapConcurrent` equivalent exists. Ruby keeps grouped write behavior through `batch` when provided.

### Organization Authorization

- [x] Port/audit structure for `upstream/packages/api-key/src/org-authorization.ts`.
- [x] Port/audit `API_KEY_PERMISSIONS`.
- [x] Port/audit organization plugin lookup and missing-plugin error.
- [x] Port/audit organization membership lookup.
- [x] Port/audit owner/creator implicit permission behavior.
- [x] Port/audit custom role permission behavior.
- [x] Port/audit read/create/update/delete action checks.

### Routes

- [x] Port/audit structure for `upstream/packages/api-key/src/routes/index.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/routes/create-api-key.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/routes/verify-api-key.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/routes/get-api-key.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/routes/update-api-key.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/routes/delete-api-key.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/routes/list-api-keys.ts`.
- [x] Port/audit structure for `upstream/packages/api-key/src/routes/delete-all-expired-api-keys.ts`.

## Ruby Target Structure

### Public Entrypoints

- [x] Keep `packages/better_auth-api-key/lib/better_auth/api_key.rb`.
- [x] Keep `packages/better_auth-api-key/lib/better_auth/api_key/version.rb`.
- [x] Keep `packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb` as the public plugin factory.
- [x] Reduce `packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb` to plugin assembly, hook wiring, endpoint registration, compatibility requires, and compatibility delegators. Endpoint factories, org authorization, schema, rate-limit helpers, utils, route-index helpers, adapter/database/storage helpers, validation, public-shape helpers, record helpers, key/session helpers, and configuration normalization have been extracted.

### Proposed Ruby Modules Mirroring Upstream

- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/error_codes.rb` for `API_KEY_ERROR_CODES`.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/schema.rb` for `api_key_schema`.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/types.rb` only if shared Ruby config/record normalization needs a stable home.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/utils.rb` for date, API error predicate, IP/header, JSON, and time helpers.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/rate_limit.rb` for rate-limit window and request-count calculations.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/adapter.rb` for database/secondary-storage CRUD and metadata migration.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/org_authorization.rb` for organization-owned key permissions.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/routes/index.rb` for config resolution, config id matching, expired cleanup, and route registry.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/routes/create_api_key.rb`.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/routes/verify_api_key.rb`.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/routes/get_api_key.rb`.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/routes/update_api_key.rb`.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/routes/delete_api_key.rb`.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/routes/list_api_keys.rb`.
- [x] Create `packages/better_auth-api-key/lib/better_auth/api_key/routes/delete_all_expired_api_keys.rb`.

### Proposed Ruby Test Files Mirroring Upstream

- [x] Keep `packages/better_auth-api-key/test/better_auth/api_key_test.rb` temporarily as broad regression coverage.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/plugin_test.rb` for `index.ts`, `client.ts`, `version.ts`, `error-codes.ts`, and hook behavior.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/schema_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/utils_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/rate_limit_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/adapter_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/org_authorization_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/keys_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/configuration_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/session_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/validation_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/routes/create_api_key_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/routes/index_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/routes/verify_api_key_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/routes/get_api_key_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/routes/update_api_key_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/routes/delete_api_key_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/routes/list_api_keys_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/routes/delete_all_expired_api_keys_test.rb`.
- [x] Create `packages/better_auth-api-key/test/better_auth/api_key/org_api_key_test.rb` for `upstream/packages/api-key/src/org-api-key.test.ts`.

## Behavior Parity Checklist

### Plugin Setup and API Key Hook

- [x] Match upstream default key hasher: SHA-256 base64url without padding.
- [x] Match upstream table name: `apikey`.
- [x] Match upstream package version exposure.
- [x] Match upstream error code names and messages.
- [x] Match upstream default config values.
- [x] Match upstream multiple-configuration validation: every array config needs `configId`.
- [x] Match upstream multiple-configuration validation: `configId` values must be unique.
- [x] Match upstream default config selection: absent, nil, empty, and `"default"` resolve as default where Ruby compatibility requires it.
- [x] Match upstream API key header lookup for one header or an array of headers.
- [x] Match upstream custom API key getter return-type validation.
- [x] Match upstream custom API key validator behavior before database validation.
- [x] Match upstream `enableSessionForAPIKeys` hook behavior.
- [x] Match upstream session shape from API key: id, token, userId, userAgent, ipAddress, createdAt, updatedAt, expiresAt.
- [x] Match upstream behavior that API key sessions only work for user-owned keys.
- [x] Match upstream invalid reference/user errors from API key sessions.
- [x] Preserve Ruby-specific IP tracking behavior when `advanced.ip_address.disable_ip_tracking` is configured.

### Create API Key

- [x] Require authenticated session for client creation.
- [x] Allow server creation with `userId`.
- [x] Reject server creation without session and without `userId`.
- [x] Reject client-supplied `userId`.
- [x] Reject client-supplied server-only fields: `permissions`, `refillAmount`, `refillInterval`, `rateLimitMax`, `rateLimitTimeWindow`.
- [x] Generate default random key using letters only with configured length.
- [x] Apply configured prefix and validate prefix characters/length.
- [x] Apply required name option.
- [x] Validate name min/max length.
- [x] Set `referenceId` instead of legacy `userId`.
- [x] Set `configId`, defaulting to `"default"`.
- [x] Set `start` from first configured characters when enabled.
- [x] Set `start` to nil/null when disabled.
- [x] Store hashed key unless `disableKeyHashing` is true.
- [x] Store raw key when `disableKeyHashing` is true.
- [x] Return full key only from create response.
- [x] Apply rate-limit defaults from plugin configuration.
- [x] Accept server-side custom rate-limit fields.
- [x] Preserve explicit `rateLimitEnabled: false`.
- [x] Default `rateLimitEnabled` to true when omitted and plugin rate limit is enabled.
- [x] Apply `keyExpiration.defaultExpiresIn`.
- [x] Accept explicit `expiresIn`.
- [x] Reject custom `expiresIn` when custom expiration is disabled.
- [x] Reject `expiresIn` below configured minimum.
- [x] Reject `expiresIn` above configured maximum.
- [x] Treat `expiresIn: nil` as no expiration where upstream uses nullable input.
- [x] Accept `remaining`.
- [x] Accept `remaining: nil`.
- [x] Accept `remaining: 0`.
- [x] Accept `refillAmount` and `refillInterval` together.
- [x] Reject `refillAmount` without `refillInterval`.
- [x] Reject `refillInterval` without `refillAmount`.
- [x] Preserve nil remaining when refill fields are present and remaining is omitted.
- [x] Reject metadata when metadata is disabled.
- [x] Reject non-object metadata.
- [x] Return metadata as an object.
- [x] Store permissions as JSON/string internally and return permissions as an object.
- [x] Apply default permissions callable or static value.
- [x] Delete expired keys after create according to upstream cleanup behavior.

### Verify API Key

- [x] Require key in request body; do not silently fall back to headers for verify.
- [x] Return `{valid: false, error, key: nil}` for invalid keys.
- [x] Return upstream error code `INVALID_API_KEY` for missing/invalid key body.
- [x] Run custom API key validator before database validation.
- [x] Hash incoming key unless hashing is disabled.
- [x] Resolve correct configuration from request `configId`.
- [x] Resolve correct configuration again from the stored key's `configId`.
- [x] Reject disabled keys with `KEY_DISABLED`.
- [x] Reject expired keys with `KEY_EXPIRED`.
- [x] Delete expired keys from the active storage/database path.
- [x] Reject exhausted non-refillable keys with `USAGE_EXCEEDED`.
- [x] Delete exhausted non-refillable keys where upstream does.
- [x] Decrement `remaining` on successful verification.
- [x] Refill remaining count only after `refillInterval` has elapsed.
- [x] Support multiple refill cycles.
- [x] Do not refill before interval elapsed.
- [x] Update `lastRequest` on successful verification.
- [x] Do not increment `requestCount` when rate limit is disabled.
- [x] Increment/reset `requestCount` according to rate-limit window.
- [x] Return `RATE_LIMITED` with `details.tryAgainIn` on rate-limit failure.
- [x] Check required permissions against stored permissions.
- [x] Return `KEY_NOT_FOUND` for permission mismatch.
- [x] Return `KEY_NOT_FOUND` when required permissions are provided but stored permissions are missing.
- [x] Return metadata and permissions as objects in successful verify result.
- [x] Support `deferUpdates` with background task handler.
- [x] Fall back to synchronous updates when no background task handler exists.
- [x] Delete expired keys synchronously unless updates are deferred.
- [x] Schedule expired cleanup in background when deferred.

### Get API Key

- [x] Require session for client get.
- [x] Allow authorized server/session get by id.
- [x] Return `KEY_NOT_FOUND` for unknown id.
- [x] Match config id before returning a key.
- [x] Reject access to another user's key as not found.
- [x] Allow organization-authorized access for org-owned keys.
- [x] Return metadata as object.
- [x] Return permissions as object.
- [x] Never return full secret key from get.
- [x] Migrate legacy double-stringified metadata on get.
- [x] Warm secondary storage from database when fallback is enabled.

### Update API Key

- [x] Require session or server-side `userId`.
- [x] Reject client update for another user.
- [x] Reject no-op update with `NO_VALUES_TO_UPDATE`.
- [x] Reject client-supplied server-only fields.
- [x] Validate name min/max length.
- [x] Update name.
- [x] Update enabled status.
- [x] Update metadata when metadata is enabled.
- [x] Reject invalid metadata type.
- [x] Ignore or reject metadata update when metadata is disabled according to upstream/Ruby compatibility decision.
- [x] Update permissions.
- [x] Update `expiresIn`.
- [x] Clear expiration when `expiresIn: nil`.
- [x] Reject custom expiration update when custom expiration is disabled.
- [x] Reject expiration below minimum.
- [x] Reject expiration above maximum.
- [x] Update `remaining` explicitly.
- [x] Preserve `remaining: 0` where upstream allows it. Upstream create accepts `remaining: 0`; upstream update requires `.min(1)`, so Ruby update rejection is intentional parity.
- [x] Update `refillAmount` and `refillInterval` together.
- [x] Reject `refillAmount` without `refillInterval`.
- [x] Reject `refillInterval` without `refillAmount`.
- [x] Do not modify `lastRequest` during configuration update.
- [x] Do not decrement `remaining` during update.
- [x] Preserve `configId`.
- [x] Migrate legacy double-stringified metadata on update.
- [x] Update both database and secondary storage when fallback is enabled.

### Delete API Key and Expired Cleanup

- [x] Require session for client delete.
- [x] Reject banned users.
- [x] Return `KEY_NOT_FOUND` for unknown id.
- [x] Match config id before delete.
- [x] Reject unauthorized user delete as not found.
- [x] Allow organization-authorized delete for org-owned keys.
- [x] Delete from database storage.
- [x] Delete from secondary storage.
- [x] Delete from both database and secondary storage when fallback is enabled.
- [x] Remove deleted id from secondary-storage reference list.
- [x] Return `{success: true}` for successful delete.
- [x] Match `deleteAllExpiredApiKeys` response shape: `{success: true, error: nil}`.
- [x] Throttle expired cleanup with the upstream last-check window unless bypassed.
- [x] Bypass last-check window for delete-all-expired endpoint.

### List API Keys

- [x] Require session for client list.
- [x] List only current user's user-owned keys when no organization id is provided.
- [x] List only organization-owned keys when organization id is provided.
- [x] Authorize organization list with read permission.
- [x] Filter by `configId`.
- [x] Return `apiKeys`, `total`, `limit`, and `offset`.
- [x] Support numeric and string query parameters for `limit` and `offset`.
- [x] Reject invalid negative pagination values.
- [x] Sort by `createdAt` ascending.
- [x] Sort by `createdAt` descending.
- [x] Sort by `name`.
- [x] Support snake_case and camelCase sort fields in Ruby.
- [x] Combine sorting and pagination.
- [x] Return empty array when offset exceeds total.
- [x] Return metadata as object.
- [x] Return permissions as object.
- [x] Migrate legacy double-stringified metadata on list.
- [x] Populate/warm secondary storage from database when fallback is enabled.
- [x] Avoid touching the ref list once per key while fallback-populating.
- [x] Fetch/populate storage keys in parallel where Ruby storage API supports it. Intentional Ruby difference: storage calls are synchronous; grouped writes are covered with the `batch` hook instead of async parallelism.

### Secondary Storage and Adapter

- [x] Support pure secondary-storage mode without database writes.
- [x] Support fallback-to-database mode.
- [x] Prefer secondary storage reads before database reads.
- [x] Auto-populate secondary storage from database on get fallback.
- [x] Auto-populate secondary storage from database on list fallback.
- [x] Persist quota/rate-limit updates to database when fallback is enabled.
- [x] Use custom storage methods instead of global secondary storage.
- [x] Use custom get method.
- [x] Use custom delete method.
- [x] Set TTL for expiring keys.
- [x] Treat expired secondary-storage keys as expired, not invalid.
- [x] Maintain reference list in pure secondary-storage mode.
- [x] Invalidate, not mutate, fallback reference list on create.
- [x] Invalidate, not mutate, fallback reference list on delete.
- [x] Avoid lost ids when creates race on the fallback reference list.
- [x] Preserve Ruby legacy read fallback for `api-key:key:*`, `api-key:id:*`, and `api-key:user:*`.
- [x] Continue writing upstream layout keys: `api-key:*`, `api-key:by-id:*`, `api-key:by-ref:*`.

### Organization-Owned API Keys

- [x] Require `organizationId` for organization-owned create.
- [x] Require organization plugin for org-owned operations.
- [x] Reject non-members.
- [x] Reject default members without apiKey permissions.
- [x] Allow organization owner/creator full CRUD.
- [x] Allow custom admin role full CRUD.
- [x] Allow read-only member to read/list but not create/update/delete.
- [x] Reject restricted roles with no apiKey permissions.
- [x] Verify organization-owned keys without creating user sessions from them.
- [x] Prevent session mocking for org-owned keys.
- [x] Allow user-owned key sessions even with organization plugin installed.
- [x] Keep user-owned and org-owned key listing separate.
- [x] Support mixed user and org keys in same auth instance.
- [x] Support org-owned get by id from server.
- [x] Support org-owned update.
- [x] Support org-owned delete.
- [x] Reject org key access with wrong `configId`.

## Upstream Test Checklist

### `upstream/packages/api-key/src/api-key.test.ts`

- [x] Port/audit: should fail to create API keys from client without headers. Covered by `test/better_auth/api_key_test.rb:1261`.
- [x] Port/audit: should successfully create API keys from client with headers. Covered by `test/better_auth/api_key_test.rb:21` and `test/better_auth/api_key/routes/create_api_key_test.rb:8`.
- [x] Port/audit: should fail to create API Keys from server without headers and userId. Covered by `test/better_auth/api_key_test.rb:1261`.
- [x] Port/audit: should fail to create api keys from the client if user id is provided. Covered by `test/better_auth/api_key_test.rb:332`.
- [x] Port/audit: should successfully create API keys from server with userId. Covered by `test/better_auth/api_key_test.rb:21`.
- [x] Port/audit: should have the real value from rateLimitEnabled. Covered by `test/better_auth/api_key_test.rb:398` and `test/better_auth/api_key/routes/create_api_key_test.rb:21`.
- [x] Port/audit: should have true if the rate limit is undefined. Covered by `test/better_auth/api_key_test.rb:1272`.
- [x] Port/audit: should require name in API keys if configured. Covered by `test/better_auth/api_key_test.rb:332`.
- [x] Port/audit: should respect rateLimit configuration from plugin options. Covered by `test/better_auth/api_key_test.rb:398` and `test/better_auth/api_key/routes/create_api_key_test.rb:21`.
- [x] Port/audit: should create the API key with the given name. Covered by `test/better_auth/api_key_test.rb:21` and `test/better_auth/api_key/routes/create_api_key_test.rb:8`.
- [x] Port/audit: should create the API key with a name that's shorter than the allowed minimum. Covered by validation boundaries in `test/better_auth/api_key_test.rb:447`.
- [x] Port/audit: should create the API key with a name that's longer than the allowed maximum. Covered by `test/better_auth/api_key_test.rb:447`.
- [x] Port/audit: should create the API key with the given prefix. Covered by `test/better_auth/api_key_test.rb:490` and `test/better_auth/api_key/routes/create_api_key_test.rb:21`.
- [x] Port/audit: should create the API key with a prefix that's shorter than the allowed minimum. Covered by validation boundaries in `test/better_auth/api_key_test.rb:447`.
- [x] Port/audit: should create the API key with a prefix that's longer than the allowed maximum. Covered by validation boundaries in `test/better_auth/api_key_test.rb:447`.
- [x] Port/audit: should create an API key with a custom expiresIn. Covered by `test/better_auth/api_key_test.rb:1283`.
- [x] Port/audit: should support disabling key hashing. Covered by `test/better_auth/api_key_test.rb:398`.
- [x] Port/audit: should be able to verify with key hashing disabled. Covered by `test/better_auth/api_key_test.rb:398`.
- [x] Port/audit: should fail to create a key with a custom expiresIn value when customExpiresTime is disabled. Covered by `test/better_auth/api_key_test.rb:1296`.
- [x] Port/audit: should create an API key with an expiresIn that's smaller than the allowed minimum. Covered by bounds tests in `test/better_auth/api_key_test.rb:447`.
- [x] Port/audit: should fail to create an API key with an expiresIn that's larger than the allowed maximum. Covered by `test/better_auth/api_key_test.rb:447`.
- [x] Port/audit: should fail to create API key with custom refillAndAmount from client auth. Covered by `test/better_auth/api_key_test.rb:435` and `test/better_auth/api_key/routes/create_api_key_test.rb:37`.
- [x] Port/audit: should fail to create API key when refill interval is provided, but no refill amount. Covered by `test/better_auth/api_key_test.rb:447`.
- [x] Port/audit: should fail to create API key when refill amount is provided, but no refill interval. Covered by `test/better_auth/api_key_test.rb:447`.
- [x] Port/audit: should create the API key with the given refill interval & refill amount. Covered by `test/better_auth/api_key_test.rb:369` and `test/better_auth/api_key/routes/create_api_key_test.rb:51`.
- [x] Port/audit: should create API Key with custom remaining. Covered by `test/better_auth/api_key_test.rb:1362`.
- [x] Port/audit: should create API Key with remaining explicitly set to null. Covered by `test/better_auth/api_key_test.rb:359`.
- [x] Port/audit: should create API Key with remaining explicitly set to null and refillAmount and refillInterval are also set. Covered by `test/better_auth/api_key_test.rb:369`.
- [x] Port/audit: should create API Key with remaining explicitly set to 0 and refillAmount also set. Covered by `test/better_auth/api_key_test.rb:447`.
- [x] Port/audit: should create API Key with remaining undefined and default value of null is respected with refillAmount and refillInterval provided. Covered by `test/better_auth/api_key_test.rb:369` and `test/better_auth/api_key/routes/create_api_key_test.rb:51`.
- [x] Port/audit: should create API key with invalid metadata. Covered by `test/better_auth/api_key_test.rb:447`.
- [x] Port/audit: should create API key with valid metadata. Covered by `test/better_auth/api_key_test.rb:21` and `test/better_auth/api_key/routes/create_api_key_test.rb:8`.
- [x] Port/audit: create API key's returned metadata should be an object. Covered by `test/better_auth/api_key_test.rb:447`.
- [x] Port/audit: create API key with with metadata when metadata is disabled (should fail). Covered by `test/better_auth/api_key_test.rb:398`.
- [x] Port/audit: should have the first 6 characters of the key as the start property. Covered by `test/better_auth/api_key/routes/create_api_key_test.rb:21`.
- [x] Port/audit: should have the start property as null if shouldStore is false. Covered by `test/better_auth/api_key_test.rb:398`.
- [x] Port/audit: should use the defined charactersLength if provided. Covered by `test/better_auth/api_key_test.rb:398`.
- [x] Port/audit: should fail to create API key with custom rate-limit options from client auth. Covered by `test/better_auth/api_key_test.rb:435` and `test/better_auth/api_key/routes/create_api_key_test.rb:37`.
- [x] Port/audit: should successfully apply custom rate-limit options on the newly created API key. Covered by `test/better_auth/api_key_test.rb:1310`.
- [x] Port/audit: verify API key without key and userId. Covered by `test/better_auth/api_key_test.rb:611` and `test/better_auth/api_key/routes/verify_api_key_test.rb:18`.
- [x] Port/audit: verify API key with invalid key (should fail). Covered by `test/better_auth/api_key_test.rb:600` and `test/better_auth/api_key/routes/verify_api_key_test.rb:8`.
- [x] Port/audit: should fail to verify API key 20 times in a row due to rate-limit. Covered by `test/better_auth/api_key_test.rb:1324`.
- [x] Port/audit: should allow us to verify API key after rate-limit window has passed. Covered by `test/better_auth/api_key_test.rb:1342`.
- [x] Port/audit: should check if verifying an API key's remaining count does go down. Covered by `test/better_auth/api_key_test.rb:1362`.
- [x] Port/audit: should fail if the API key has no remaining. Covered by `test/better_auth/api_key_test.rb:705`.
- [x] Port/audit: should fail if the API key is expired. Covered by `test/better_auth/api_key_test.rb:1190`.
- [x] Port/audit: should fail to update API key name without headers or userId. Covered by `test/better_auth/api_key_test.rb:930`.
- [x] Port/audit: should update API key name with headers. Covered by `test/better_auth/api_key/routes/update_api_key_test.rb:8`.
- [x] Port/audit: should fail to update API key name with a length larger than the allowed maximum. Covered by `test/better_auth/api_key_test.rb:1002`.
- [x] Port/audit: should fail to update API key name with a length smaller than the allowed minimum. Covered by `test/better_auth/api_key_test.rb:1002`.
- [x] Port/audit: should fail to update API key with no values to update. Covered by `test/better_auth/api_key/routes/update_api_key_test.rb:20`.
- [x] Port/audit: should update API key expiresIn value. Covered by `test/better_auth/api_key_test.rb:1002`.
- [x] Port/audit: should fail to update expiresIn value if `disableCustomExpiresTime` is enabled. Covered by `test/better_auth/api_key_test.rb:1378`.
- [x] Port/audit: should fail to update expiresIn value if it's smaller than the allowed minimum. Covered by `test/better_auth/api_key_test.rb:1393` and `test/better_auth/api_key/routes/update_api_key_test.rb:68`.
- [x] Port/audit: should fail to update expiresIn value if it's larger than the allowed maximum. Covered by `test/better_auth/api_key_test.rb:1408` and `test/better_auth/api_key/routes/update_api_key_test.rb:68`.
- [x] Port/audit: should update API key remaining count. Covered by `test/better_auth/api_key_test.rb:1055` and `test/better_auth/api_key/routes/update_api_key_test.rb:42`.
- [x] Port/audit: should fail update the refillInterval value since it requires refillAmount as well. Covered by `test/better_auth/api_key_test.rb:973`.
- [x] Port/audit: should fail update the refillAmount value since it requires refillInterval as well. Covered by `test/better_auth/api_key_test.rb:973` and `test/better_auth/api_key/routes/update_api_key_test.rb:68`.
- [x] Port/audit: should update the refillInterval and refillAmount value. Covered by `test/better_auth/api_key_test.rb:973` and `test/better_auth/api_key_test.rb:1002`.
- [x] Port/audit: should update API key enable value. Covered by `test/better_auth/api_key/routes/update_api_key_test.rb:42`.
- [x] Port/audit: should fail to update metadata with invalid metadata type. Covered by `test/better_auth/api_key_test.rb:1002`.
- [x] Port/audit: should update metadata with valid metadata type. Covered by `test/better_auth/api_key_test.rb:1002` and `test/better_auth/api_key/routes/update_api_key_test.rb:42`.
- [x] Port/audit: update API key's returned metadata should be an object. Covered by `test/better_auth/api_key_test.rb:1002`.
- [x] Port/audit: should not modify lastRequest when updating API key configuration. Covered by `test/better_auth/api_key_test.rb:1055` and `test/better_auth/api_key/routes/update_api_key_test.rb:8`.
- [x] Port/audit: should not auto-decrement remaining when updating API key. Covered by `test/better_auth/api_key_test.rb:1055`.
- [x] Port/audit: should allow explicit remaining updates via body parameter. Covered by `test/better_auth/api_key_test.rb:1055`.
- [x] Port/audit: verifyApiKey should still update lastRequest. Covered by `test/better_auth/api_key_test.rb:1055`.
- [x] Port/audit: verifyApiKey should still decrement remaining. Covered by `test/better_auth/api_key_test.rb:1055` and `test/better_auth/api_key_test.rb:1362`.
- [x] Port/audit: should get an API key by id. Covered by `test/better_auth/api_key/routes/get_api_key_test.rb:8`.
- [x] Port/audit: should fail to get an API key by ID that doesn't exist. Covered by `test/better_auth/api_key/routes/get_api_key_test.rb:19`.
- [x] Port/audit: should successfully receive an object metadata from an API key. Covered by `test/better_auth/api_key/routes/get_api_key_test.rb:19`.
- [x] Port/audit: should fail to list API keys without headers. Covered by `test/better_auth/api_key/routes/list_api_keys_test.rb:22`.
- [x] Port/audit: should list API keys with headers. Covered by `test/better_auth/api_key/routes/list_api_keys_test.rb:8`.
- [x] Port/audit: should list API keys with metadata as an object. Covered by `test/better_auth/api_key_test.rb:1076`.
- [x] Port/audit: should return paginated response with total count. Covered by `test/better_auth/api_key/routes/list_api_keys_test.rb:8`.
- [x] Port/audit: should limit the number of returned API keys. Covered by `test/better_auth/api_key/routes/list_api_keys_test.rb:8`.
- [x] Port/audit: should skip API keys with offset. Covered by `test/better_auth/api_key/routes/list_api_keys_test.rb:8`.
- [x] Port/audit: should support pagination with both limit and offset. Covered by `test/better_auth/api_key_test.rb:1437` and `test/better_auth/api_key/routes/list_api_keys_test.rb:8`.
- [x] Port/audit: should sort API keys by createdAt ascending. Covered by `test/better_auth/api_key_test.rb:558`.
- [x] Port/audit: should sort API keys by createdAt descending. Covered by `test/better_auth/api_key_test.rb:1452` and `test/better_auth/api_key/routes/list_api_keys_test.rb:54`.
- [x] Port/audit: should sort API keys by name. Covered by `test/better_auth/api_key_test.rb:573`.
- [x] Port/audit: should combine sorting with pagination. Covered by `test/better_auth/api_key_test.rb:1469`.
- [x] Port/audit: should return empty array when offset exceeds total. Covered by `test/better_auth/api_key/routes/list_api_keys_test.rb:54`.
- [x] Port/audit: should handle string query parameters for limit and offset. Covered by `test/better_auth/api_key/routes/list_api_keys_test.rb:8`.
- [x] Port/audit: should get session from an API key. Covered by `test/better_auth/api_key/plugin_test.rb:41`.
- [x] Port/audit: should not get session from an API key if enableSessionForAPIKeys is false. Covered by `test/better_auth/api_key_test.rb:140`.
- [x] Port/audit: should get the Response object when asResponse is true or mark intentionally different for Ruby API. Ruby does not expose the TypeScript client `asResponse` surface; classify as intentionally different unless a Ruby response wrapper API is added.
- [x] Port/audit: should fail to delete an API key by ID without headers. Covered by `test/better_auth/api_key_test.rb:1423`.
- [x] Port/audit: should delete an API key by ID with headers. Covered by `test/better_auth/api_key/routes/delete_api_key_test.rb:8`.
- [x] Port/audit: should delete an API key by ID with headers using auth-client or mark intentionally different for Ruby API. Ruby has endpoint/server invocation tests, but no TypeScript `auth-client` surface; classify as intentionally different for this package.
- [x] Port/audit: should fail to delete an API key by ID that doesn't exist. Covered by `test/better_auth/api_key/routes/delete_api_key_test.rb:19`.
- [x] Port/audit: should create an API key with permissions. Covered by `test/better_auth/api_key_test.rb:21`.
- [x] Port/audit: should have permissions as an object from getApiKey. Covered by `test/better_auth/api_key/routes/get_api_key_test.rb:19`.
- [x] Port/audit: should have permissions as an object from verifyApiKey. Covered by `test/better_auth/api_key/routes/verify_api_key_test.rb:43`.
- [x] Port/audit: should create an API key with default permissions. Covered by `test/better_auth/api_key_test.rb:735`.
- [x] Port/audit: should have valid metadata from key verification results. Covered by `test/better_auth/api_key/routes/verify_api_key_test.rb:43`.
- [x] Port/audit: should verify an API key with matching permissions. Covered by `test/better_auth/api_key/routes/verify_api_key_test.rb:43`.
- [x] Port/audit: should fail to verify an API key with non-matching permissions. Covered by `test/better_auth/api_key_test.rb:638` and `test/better_auth/api_key/routes/verify_api_key_test.rb:43`.
- [x] Port/audit: should fail to verify when required permissions are specified but API key has no permissions. Covered by `test/better_auth/api_key_test.rb:679`.
- [x] Port/audit: should update an API key with permissions. Covered by `test/better_auth/api_key_test.rb:930` and `test/better_auth/api_key/routes/update_api_key_test.rb:42`.
- [x] Port/audit: should refill API key credits after refill interval (milliseconds). Covered by `test/better_auth/api_key_test.rb:705`.
- [x] Port/audit: should not refill API key credits before refill interval expires. Covered by `test/better_auth/api_key_test.rb:705`.
- [x] Port/audit: should handle multiple refill cycles correctly. Covered by `test/better_auth/api_key_test.rb:705`.
- [x] Port/audit: should create API key in secondary storage. Covered by `test/better_auth/api_key_test.rb:263`.
- [x] Port/audit: should get API key from secondary storage. Covered by `test/better_auth/api_key_test.rb:263`.
- [x] Port/audit: should list API keys from secondary storage. Covered by `test/better_auth/api_key_test.rb:263`.
- [x] Port/audit: should fetch keys from secondary storage in parallel, not sequentially. Intentionally different: Ruby secondary storage is synchronous; batch/grouping behavior is covered by `test/better_auth/api_key_test.rb:206`.
- [x] Port/audit: should update API key in secondary storage. Covered by `test/better_auth/api_key_test.rb:263`.
- [x] Port/audit: should delete API key in secondary storage. Covered by `test/better_auth/api_key/routes/delete_api_key_test.rb:45`.
- [x] Port/audit: should verify API key from secondary storage. Covered by `test/better_auth/api_key_test.rb:94` and `test/better_auth/api_key_test.rb:263`.
- [x] Port/audit: should set TTL when API key has expiration. Covered by `test/better_auth/api_key/adapter_test.rb:33`.
- [x] Port/audit: should handle metadata in secondary storage. Covered by `test/better_auth/api_key_test.rb:263`.
- [x] Port/audit: should handle rate limiting with secondary storage. Covered by `test/better_auth/api_key_test.rb:263`.
- [x] Port/audit: should handle remaining count with secondary storage. Covered by `test/better_auth/api_key_test.rb:263`.
- [x] Port/audit: should handle expired keys with TTL in secondary storage. Covered by `test/better_auth/api_key_test.rb:1488`.
- [x] Port/audit: should maintain user's API key list in secondary storage. Covered by `test/better_auth/api_key_test.rb:1507`.
- [x] Port/audit: should read from secondary storage first. Covered by `test/better_auth/api_key_test.rb:1527`.
- [x] Port/audit: verifyApiKey should persist quota updates to the database when fallbackToDatabase is true. Covered by `test/better_auth/api_key_test.rb:1541`.
- [x] Port/audit: should fallback to database when not found in storage and auto-populate storage. Covered by `test/better_auth/api_key_test.rb:242`.
- [x] Port/audit: should populate storage when listing keys falls back to database. Covered by `test/better_auth/api_key_test.rb:1561`.
- [x] Port/audit: should populate storage in parallel when listing falls back to database. Intentionally different: Ruby storage is synchronous; population grouping/reference-list behavior is covered by `test/better_auth/api_key_test.rb:1561` and `test/better_auth/api_key_test.rb:1581`.
- [x] Port/audit: should not touch the ref list per key while populating. Covered by `test/better_auth/api_key_test.rb:1581`.
- [x] Port/audit: should invalidate (not mutate) the ref list on create. Covered by `test/better_auth/api_key_test.rb:221`.
- [x] Port/audit: should invalidate (not mutate) the ref list on delete. Covered by `test/better_auth/api_key_test.rb:221`.
- [x] Port/audit: should not lose ids when two creates race on the ref list. Covered by Ruby fallback invalidation semantics in `test/better_auth/api_key_test.rb:221`.
- [x] Port/audit: should write to secondary storage only. Covered by `test/better_auth/api_key_test.rb:1597`.
- [x] Port/audit: should create in both database and secondary storage when fallbackToDatabase is true. Covered by `test/better_auth/api_key_test.rb:1609`.
- [x] Port/audit: should update both database and secondary storage when fallbackToDatabase is true. Covered by `test/better_auth/api_key_test.rb:1623`.
- [x] Port/audit: should delete from both database and secondary storage when fallbackToDatabase is true. Covered by `test/better_auth/api_key_test.rb:1639`.
- [x] Port/audit: should defer updates when deferUpdates is enabled with global backgroundTasks. Covered by `test/better_auth/api_key_test.rb:1233`.
- [x] Port/audit: should still validate rate limits correctly with deferred updates. Covered by `test/better_auth/api_key_test.rb:1653`.
- [x] Port/audit: should defer remaining count updates. Covered by `test/better_auth/api_key_test.rb:1681`.
- [x] Port/audit: should not defer updates when backgroundTasks handler is not configured. Covered by `test/better_auth/api_key_test.rb:1702`.
- [x] Port/audit: should use custom storage methods instead of global secondaryStorage. Covered by `test/better_auth/api_key/adapter_test.rb:66`.
- [x] Port/audit: should use custom get method. Covered by `test/better_auth/api_key/adapter_test.rb:66` and `test/better_auth/api_key_test.rb:263`.
- [x] Port/audit: should use custom delete method. Covered by `test/better_auth/api_key/adapter_test.rb:66` and `test/better_auth/api_key_test.rb:263`.
- [x] Port/audit: should migrate double-stringified metadata on getApiKey. Covered by `test/better_auth/api_key_test.rb:1171` and `test/better_auth/api_key/adapter_test.rb:35`.
- [x] Port/audit: should migrate double-stringified metadata on listApiKeys. Covered by `test/better_auth/api_key_test.rb:1716`.
- [x] Port/audit: should migrate double-stringified metadata on updateApiKey. Covered by `test/better_auth/api_key_test.rb:1737`.
- [x] Port/audit: should migrate double-stringified metadata on verifyApiKey. Covered by `test/better_auth/api_key_test.rb:1171`.
- [x] Port/audit: should handle already properly formatted metadata (no migration needed). Covered by `test/better_auth/api_key_test.rb:1752` and `test/better_auth/api_key/adapter_test.rb:53`.
- [x] Port/audit: should handle null metadata gracefully. Covered by `test/better_auth/api_key_test.rb:1763` and `test/better_auth/api_key/adapter_test.rb:53`.
- [x] Port/audit: should create API key with specific configId. Covered by `test/better_auth/api_key_test.rb:490`.
- [x] Port/audit: should use default config when no configId is provided. Covered by `test/better_auth/api_key_test.rb:490`.
- [x] Port/audit: should list keys filtered by configId. Covered by `test/better_auth/api_key/routes/list_api_keys_test.rb:35`.
- [x] Port/audit: should verify key and apply correct config rate limits. Covered by `test/better_auth/api_key_test.rb:521`.
- [x] Port/audit: should get key and resolve correct config. Covered by `test/better_auth/api_key_test.rb:521`.
- [x] Port/audit: should update key while preserving configId. Covered by `test/better_auth/api_key/routes/update_api_key_test.rb:42`.
- [x] Port/audit: should delete key from specific config. Covered by `test/better_auth/api_key_test.rb:521`.
- [x] Port/audit: should throw error when configId array has non-unique configIds. Covered by `test/better_auth/api_key/configuration_test.rb:18`.
- [x] Port/audit: should throw error when configId is missing in array config. Covered by `test/better_auth/api_key/configuration_test.rb:18`.
- [x] Port/audit: should create organization-owned API key. Covered by `test/better_auth/api_key/org_api_key_test.rb:22`.
- [x] Port/audit: should create user-owned API key. Covered by `test/better_auth/api_key/org_api_key_test.rb:39`.
- [x] Port/audit: should fail to create org key without organizationId. Covered by `test/better_auth/api_key_test.rb:1774`.
- [x] Port/audit: should verify organization-owned API key. Covered by `test/better_auth/api_key_test.rb:1888`.
- [x] Port/audit: should list only user-owned keys when no organizationId provided. Covered by `test/better_auth/api_key/org_api_key_test.rb:39`.
- [x] Port/audit: should list organization-owned keys when organizationId is provided. Covered by `test/better_auth/api_key/org_api_key_test.rb:39`.
- [x] Port/audit: should filter organization keys by configId. Covered by `test/better_auth/api_key_test.rb:1823`.
- [x] Port/audit: should allow organization owners to manage API keys. Covered by `test/better_auth/api_key/org_api_key_test.rb:22`.
- [x] Port/audit: should deny non-members from accessing organization API keys. Covered by `test/better_auth/api_key_test.rb:1950`.
- [x] Port/audit: should not allow session mocking for org-owned keys. Covered by `test/better_auth/api_key_test.rb:1847`.
- [x] Port/audit: should allow session mocking for user-owned keys only. Covered by `test/better_auth/api_key_test.rb:1868`.
- [x] Port/audit: should handle mixed user and org keys in same instance. Covered by `test/better_auth/api_key_test.rb:1888`.
- [x] Port/audit: should get org-owned key by id from server. Covered by `test/better_auth/api_key_test.rb:1906`.
- [x] Port/audit: should delete org-owned key. Covered by `test/better_auth/api_key_test.rb:1921`.
- [x] Port/audit: should update org-owned key. Covered by `test/better_auth/api_key_test.rb:1935`.

### `upstream/packages/api-key/src/org-api-key.test.ts`

- [x] Port/audit: organization owner should have full CRUD access to API keys. Covered by `test/better_auth/api_key/org_api_key_test.rb:22`.
- [x] Port/audit: non-member should be denied access to organization API keys. Covered by `test/better_auth/api_key_test.rb:1950`.
- [x] Port/audit: member without apiKey permissions should be denied (default roles). Covered by `test/better_auth/api_key_test.rb:1961`.
- [x] Port/audit: should correctly separate user and org keys when listing. Covered by `test/better_auth/api_key/org_api_key_test.rb:39`.
- [x] Port/audit: verify API key should work for organization-owned keys. Covered by `test/better_auth/api_key_test.rb:1888`.
- [x] Port/audit: admin role should have full apiKey CRUD permissions. Covered by `test/better_auth/api_key_test.rb:874`.
- [x] Port/audit: member role with read-only permission should be limited. Covered by `test/better_auth/api_key/org_api_key_test.rb:56`.
- [x] Port/audit: restricted role with no apiKey permissions should be fully denied. Covered by `test/better_auth/api_key_test.rb:2009`.
- [x] Port/audit: should return error when organization plugin is not installed. Covered by `test/better_auth/api_key/org_api_key_test.rb:10`.
- [x] Port/audit: should not allow accessing org key with wrong configId. Covered by `test/better_auth/api_key_test.rb:831`.

## Initial Parity Matrix

| Upstream area | Upstream source/tests | Ruby target | Initial Ruby status | Notes |
| --- | --- | --- | --- | --- |
| Plugin entrypoint/config/hook | `src/index.ts`, `src/client.ts`, `src/version.ts`, `src/error-codes.ts` | `plugins/api_key.rb`, `api_key/plugin_test.rb`, `api_key/keys_test.rb`, `api_key/session_test.rb` | Covered | Error codes/types/version, key generation/header lookup, and API-key-session hook cases have focused tests; TypeScript client-only response/auth-client cases are intentionally different for Ruby. |
| Schema | `src/schema.ts` | `api_key/schema.rb`, `schema_test.rb` | Covered | Focused tests cover field set, required/index/default attributes, rate-limit defaults, referenceId shape, and custom schema merge/override behavior. |
| Utils | `src/utils.ts` | `api_key/utils.rb`, `utils_test.rb` | Covered | Focused tests cover JSON/time normalization, public response shaping, sorting, list-query validation, and error payload mapping. |
| Rate limit | `src/rate-limit.ts` | `api_key/rate_limit.rb`, `rate_limit_test.rb` | Covered | Extracted pure rate-limit helpers for retry/count calculations and route behavior is covered through verify tests. |
| Adapter/storage | `src/adapter.ts` | `api_key/adapter.rb`, `adapter_test.rb` | Covered | Storage key layout, secondary-storage helpers, reference-list helpers, serialization/deserialization, TTL behavior, database CRUD, deferred update orchestration, and metadata migration now live in adapter module. |
| Validation | create/update/verify validation paths in `api-key.test.ts` | `api_key/validation.rb`, `validation_test.rb` | Covered | Focused tests cover server-only field rejection, refill pairing, update payload preservation/encoding, refill usage updates, and permission failure code mapping. |
| Routes index/config cleanup | `src/routes/index.ts` | `routes/index.rb`, `routes/index_test.rb` | Covered | Focused tests cover config resolution/default matching and expired cleanup throttle/bypass behavior. |
| Create route | `src/routes/create-api-key.ts` and create tests in `api-key.test.ts` | `routes/create_api_key.rb`, `routes/create_api_key_test.rb` | Covered | Focused tests cover upstream record shape, hashing/start/rate-limit defaults, client server-only rejection, nil expiration, refill-without-remaining behavior, and create-triggered expired cleanup. |
| Verify route | `src/routes/verify-api-key.ts` and verify tests in `api-key.test.ts` | `routes/verify_api_key.rb`, `routes/verify_api_key_test.rb` | Covered | Focused tests cover invalid payloads, no header fallback, rate-limit details, permission checks, public response shape, metadata, and permissions decoding. |
| Get route | `src/routes/get-api-key.ts` and get tests in `api-key.test.ts` | `routes/get_api_key.rb`, `routes/get_api_key_test.rb` | Covered | Focused tests cover no-secret shape, decoded metadata/permissions, missing id, and wrong-user not-found behavior. |
| Update route | `src/routes/update-api-key.ts` and update tests in `api-key.test.ts` | `routes/update_api_key.rb`, `routes/update_api_key_test.rb` | Covered | Focused tests cover usage-field preservation, no-op rejection, authenticated client server-only rejection, server-side mutations, config preservation, refill pairing, and expiration bounds. |
| Delete route | `src/routes/delete-api-key.ts` and delete tests in `api-key.test.ts` | `routes/delete_api_key.rb`, `routes/delete_api_key_test.rb` | Covered | Focused tests cover successful delete, missing id, wrong-user not-found behavior, secondary-storage key deletion, and reference-list cleanup. |
| List route | `src/routes/list-api-keys.ts` and list tests in `api-key.test.ts` | `routes/list_api_keys.rb`, `routes/list_api_keys_test.rb` | Covered | Focused tests cover pagination/string query shape, auth requirement, invalid query rejection, config filtering, hidden secret keys, createdAt sorting, and offset overflow. |
| Delete expired endpoint | `src/routes/delete-all-expired-api-keys.ts` | `routes/delete_all_expired_api_keys.rb`, `routes/delete_all_expired_api_keys_test.rb`, `routes/index_test.rb` | Covered | Endpoint factory lives in route module; response shape, cleanup throttle, and bypass behavior have focused tests. |
| Organization auth | `src/org-authorization.ts`, `src/org-api-key.test.ts` | `api_key/org_authorization.rb`, `org_authorization_test.rb`, `org_api_key_test.rb` | Covered | Focused tests cover permission constant, missing organization plugin, owner CRUD, user/org list separation, read-only member access boundaries, and broader role matrix coverage remains in the monolith. |

## Execution Order

### Phase 1: Inventory and Matrix

- [x] Count upstream `describe` / `it` blocks in `upstream/packages/api-key/src/api-key.test.ts`.
- [x] Count upstream `describe` / `it` blocks in `upstream/packages/api-key/src/org-api-key.test.ts`.
- [x] Count Ruby tests in `packages/better_auth-api-key/test/better_auth/api_key_test.rb`.
- [x] For every upstream test checkbox above, mark `covered`, `partial`, `not ported`, or `intentionally different`.
- [x] Add file/line references from existing Ruby tests for every `covered` or `partial` item.
- [x] Identify Ruby compatibility additions that do not exist upstream, including legacy secondary-storage key layouts and snake_case input compatibility.
- [x] Commit only the plan/matrix updates.

### Phase 2: Structure Split Without Behavior Changes

- [x] Extract error codes into `api_key/error_codes.rb`.
- [x] Extract schema into `api_key/schema.rb`.
- [x] Extract utils into `api_key/utils.rb`.
- [x] Extract rate-limit helpers into `api_key/rate_limit.rb`.
- [x] Extract adapter/storage helpers into `api_key/adapter.rb`.
- [x] Extract organization authorization into `api_key/org_authorization.rb`.
- [x] Extract route registry/config cleanup into `api_key/routes/index.rb`.
- [x] Extract create route into `api_key/routes/create_api_key.rb`.
- [x] Extract verify route into `api_key/routes/verify_api_key.rb`.
- [x] Extract get route into `api_key/routes/get_api_key.rb`.
- [x] Extract update route into `api_key/routes/update_api_key.rb`.
- [x] Extract delete route into `api_key/routes/delete_api_key.rb`.
- [x] Extract list route into `api_key/routes/list_api_keys.rb`.
- [x] Extract delete-expired route into `api_key/routes/delete_all_expired_api_keys.rb`.
- [x] Keep `plugins/api_key.rb` as the delegating plugin factory.
- [x] Run `rbenv exec bundle exec rake test` from `packages/better_auth-api-key`.
- [x] Commit structure changes in the API key implementation commit.

### Phase 3: Test File Parity

- [x] Create mirrored test files listed in "Proposed Ruby Test Files Mirroring Upstream".
- [x] Move or duplicate focused assertions out of the monolithic test into route/module files.
- [x] Keep the monolithic test as broad end-to-end regression coverage while mirrored files carry focused parity assertions.
- [x] Port missing upstream create tests.
- [x] Port missing upstream verify tests.
- [x] Port missing upstream get tests.
- [x] Port missing upstream update tests.
- [x] Port missing upstream delete tests.
- [x] Port missing upstream list tests.
- [x] Port missing upstream secondary-storage tests.
- [x] Port missing upstream deferred-update tests.
- [x] Port missing upstream custom-storage tests.
- [x] Port missing upstream metadata-migration tests.
- [x] Port missing upstream multiple-configuration tests.
- [x] Port missing upstream organization-owned tests.
- [x] Mark Response-object/auth-client-only upstream tests as intentionally different if Ruby has no equivalent surface.
- [x] Run focused Ruby test coverage through `rbenv exec bundle exec rake test`.
- [x] Commit test ports in the API key implementation commit.

### Phase 4: Behavior Gap Fixes

- [x] Implement only the code needed for newly ported failing tests.
- [x] Preserve current public Ruby API shape unless upstream behavior requires an intentional breaking-change note.
- [x] Keep behavior changes scoped to the matching module.
- [x] Update the matrix when a behavior is covered or intentionally different.
- [x] Run focused tests after each behavior fix.
- [x] Commit behavior fixes in the API key implementation commit.

### Phase 5: Final Verification

- [x] Run `rbenv exec bundle exec rake test` from `packages/better_auth-api-key`.
- [x] Run every new mirrored API key test file through `rbenv exec bundle exec rake test`.
- [x] Run `rbenv exec bundle exec rake test` from `packages/better_auth-api-key`.
- [x] Run `rbenv exec bundle exec standardrb` from `packages/better_auth-api-key`.
- [x] No repo-level run needed because changes are contained to `packages/better_auth-api-key`; package-level test suite exercises the shared integration surface used by this package.
- [x] Confirm no upstream test checkbox remains unclassified.
- [x] Confirm every intentional Ruby difference has a note in this plan.
- [x] Commit final matrix and cleanup.

## Commit Strategy

- [x] Commit plan and matrix updates separately from code.
- [x] Commit structure extraction, behavior fixes, and focused tests as one API key implementation commit because the accumulated implementation was already verified together.
- [x] Commit route/module test ports in the same API key implementation commit, grouped under the package boundary.
- [x] Commit behavior gap fixes with their focused tests in the same API key implementation commit.
- [x] Do not include unrelated dirty worktree changes from SSO/OAuth packages.
