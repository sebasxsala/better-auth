# better_auth-api-key

API key plugin package for Better Auth Ruby.

## Installation

Add the gem and require the package before configuring the plugin:

```ruby
gem "better_auth-api-key"
```

```ruby
require "better_auth/api_key"

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: :memory,
  plugins: [
    BetterAuth::Plugins.api_key
  ]
)
```

## Notes

This package matches upstream's separate `@better-auth/api-key` package boundary. The Ruby plugin keeps the public `BetterAuth::Plugins.api_key` entrypoint, while core `better_auth` only provides a compatibility shim.

## Upstream parity

The Ruby package implements the upstream server contract for `@better-auth/api-key`: the same API key routes, response shapes, error messages, metadata/permissions decoding, organization-owned keys, multiple configurations, rate limits, usage limits, secondary storage, fallback-to-database behavior, and API-key-backed sessions.

Frontend applications should use the upstream JavaScript client plugin against the Ruby server:

```ts
import { createAuthClient } from "better-auth/client";
import { apiKeyClient } from "@better-auth/api-key/client";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com",
  plugins: [apiKeyClient()]
});
```

Ruby does not expose a separate `apiKeyClient()` equivalent; the public Ruby surface is the server plugin and route contract.

| Method | Path | Ruby API method |
| --- | --- | --- |
| `POST` | `/api-key/create` | `auth.api.create_api_key` |
| `POST` | `/api-key/verify` | `auth.api.verify_api_key` |
| `GET` | `/api-key/get` | `auth.api.get_api_key` |
| `GET` | `/api-key/list` | `auth.api.list_api_keys` |
| `POST` | `/api-key/update` | `auth.api.update_api_key` |
| `POST` | `/api-key/delete` | `auth.api.delete_api_key` |
| `POST` | `/api-key/delete-all-expired-api-keys` | `auth.api.delete_all_expired_api_keys` |

## Operational notes

Expired API key cleanup runs against the database when `storage` is `"database"`
or `fallback_to_database` is true. Secondary-storage-only deployments should
align Redis or KV TTLs with API key expiration because database cleanup does not
purge secondary-only keys.

The scheduled expired-key cleanup throttle is per Ruby process. It is not
coordinated across web workers, hosts, or background job runners.

When `defer_updates` is combined with `advanced.background_tasks.handler`, usage
updates such as request counts, remaining limits, refill state, and scheduled
cleanup can be reordered under concurrency. Use database transactions or
deployment-level coordination if strict counters are required.

## Configuration

```ruby
auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  secondary_storage: redis_storage,
  plugins: [
    BetterAuth::Plugins.api_key(
      default_key_length: 64,
      default_prefix: "ba_",
      enable_metadata: true,
      enable_session_for_api_keys: true,
      disable_key_hashing: false,
      rate_limit: {
        enabled: true,
        time_window: 86_400_000,
        max_requests: 10
      },
      key_expiration: {
        default_expires_in: nil,
        disable_custom_expires_time: false,
        min_expires_in: 1,
        max_expires_in: 365
      },
      starting_characters_config: {
        should_store: true,
        characters_length: 6
      },
      storage: "secondary-storage",
      fallback_to_database: true,
      custom_storage: nil,
      permissions: {
        default_permissions: {files: ["read"]}
      }
    )
  ]
)
```

Multiple configurations are supported with required unique `config_id` values:

```ruby
BetterAuth::Plugins.api_key([
  {config_id: "user-keys", references: "user", default_prefix: "usr_"},
  {config_id: "org-keys", references: "organization", default_prefix: "org_"}
])
```

Organization-owned keys require `BetterAuth::Plugins.organization` and use organization permissions for `apiKey` actions: `create`, `read`, `update`, and `delete`.

Secondary-storage mode uses upstream storage keys such as `api-key:<hash>`, `api-key:by-id:<id>`, and `api-key:by-ref:<referenceId>`. When `fallback_to_database: true` is enabled, the reference list is treated as a cache and invalidated on writes/deletes so concurrent writers cannot lose IDs; listing falls back to the database source of truth.

## Storage layout

The Ruby gem writes only to the upstream layout; legacy prefixes are read for
backward compatibility but never produced by new writes:

| Purpose                          | Upstream key (read + write) | Ruby legacy key (read only) |
|----------------------------------|------------------------------|------------------------------|
| Lookup by hashed key             | `api-key:<hash>`             | `api-key:key:<hash>`         |
| Lookup by id                     | `api-key:by-id:<id>`         | `api-key:id:<id>`            |
| Reference -> [id] list           | `api-key:by-ref:<refId>`     | `api-key:user:<userId>`      |

When upgrading from older Ruby releases the new server transparently keeps
serving cached entries from the legacy keys while populating the upstream layout
on the next mutation. Once a key is rewritten, the legacy entry is also deleted
on `delete-api-key` to keep the layout converging on a single source of truth.

## Plugin metadata

The plugin object exposes the package version (mirroring upstream
`@better-auth/api-key` 1.6.0+):

```ruby
auth.options.plugins.find { |plugin| plugin.id == "api-key" }.version
# => BetterAuth::APIKey::VERSION
```

## Hashing

The upstream `defaultKeyHasher` equivalent is available as:

```ruby
BetterAuth::Plugins.default_api_key_hasher("secret-key")
BetterAuth::APIKey.default_key_hasher("secret-key")
```

Both return the SHA-256 base64url digest used for stored API keys when `disable_key_hashing` is false.

## Ruby option naming policy

Public option keys use idiomatic Ruby `snake_case` while the wire JSON keeps
upstream's `camelCase`. The mapping is fixed and intentionally lossless:

| Ruby option (snake_case)              | Wire field (camelCase)        |
|---------------------------------------|-------------------------------|
| `config_id`                           | `configId`                    |
| `default_key_length`                  | `defaultKeyLength`            |
| `default_prefix`                      | `defaultPrefix`               |
| `enable_metadata`                     | `enableMetadata`              |
| `disable_key_hashing`                 | `disableKeyHashing`           |
| `require_name`                        | `requireName`                 |
| `enable_session_for_api_keys`         | `enableSessionForAPIKeys`     |
| `fallback_to_database`                | `fallbackToDatabase`          |
| `custom_storage`                      | `customStorage`               |
| `defer_updates`                       | `deferUpdates`                |
| `references`                          | `references`                  |
| `key_expiration.default_expires_in`   | `keyExpiration.defaultExpiresIn` |
| `key_expiration.disable_custom_expires_time` | `keyExpiration.disableCustomExpiresTime` |
| `key_expiration.max_expires_in`       | `keyExpiration.maxExpiresIn`  |
| `key_expiration.min_expires_in`       | `keyExpiration.minExpiresIn`  |
| `starting_characters_config.should_store` | `startingCharactersConfig.shouldStore` |
| `starting_characters_config.characters_length` | `startingCharactersConfig.charactersLength` |
| `rate_limit.enabled`                  | `rateLimit.enabled`           |
| `rate_limit.time_window`              | `rateLimit.timeWindow`        |
| `rate_limit.max_requests`             | `rateLimit.maxRequests`       |

Endpoint requests/responses always use the upstream `camelCase` field names, so
TypeScript clients targeting `@better-auth/api-key/client` interoperate without
configuration changes.

The cleanup route is also exposed through `auth.api.delete_all_expired_api_keys`
and returns `{success: true, error: nil}` on success.

## Organization-owned API keys

Setting `references: "organization"` on a configuration delegates ownership to
`BetterAuth::Plugins::Organization`, which must be installed alongside this
plugin. The organization plugin's access-control bundle must define the
`apiKey` resource with `create`, `read`, `update`, and `delete` actions:

```ruby
ac = BetterAuth::Plugins.create_access_control(
  organization: ["update", "delete"],
  member: ["create", "update", "delete"],
  invitation: ["create", "cancel"],
  team: ["create", "update", "delete"],
  ac: ["create", "read", "update", "delete"],
  apiKey: ["create", "read", "update", "delete"]
)
```

The configured `creator_role` (default `"owner"`) is treated as having
implicit permission for every `apiKey` action, mirroring upstream's "owner
bypasses per-action permission check" behavior. All other roles must be granted
the appropriate `apiKey:*` permission to perform the corresponding action.

## Intentional Ruby-vs-upstream adaptations

The following decisions are explicit and locked behind tests:

- **OpenAPI metadata blocks** embedded in upstream endpoint definitions are not
  ported. OpenAPI generation is not part of `better_auth-api-key`'s scope.
- **Browser-only `@better-auth/api-key/client`** helpers are not implemented in
  Ruby. Apps should call `/api-key/create`, `/api-key/verify`, `/api-key/get`,
  `/api-key/list`, `/api-key/update`, `/api-key/delete`, and
  `/api-key/delete-all-expired-api-keys` directly via JSON.
- **`apikey` table name** mirrors the upstream package (no `_` separator).
- **Legacy secondary-storage prefixes** (`api-key:key:*`, `api-key:id:*`,
  `api-key:user:*`) are still honored on read so existing deployments do not
  lose data when upgrading. New writes always use the upstream layout
  documented above.
