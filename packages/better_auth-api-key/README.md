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

## Hashing

The upstream `defaultKeyHasher` equivalent is available as:

```ruby
BetterAuth::Plugins.default_api_key_hasher("secret-key")
BetterAuth::APIKey.default_key_hasher("secret-key")
```

Both return the SHA-256 base64url digest used for stored API keys when `disable_key_hashing` is false.
