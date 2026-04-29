# Better Auth SCIM

External SCIM provisioning plugin package for `better_auth`.

SCIM is not login. It is a provisioning API used by identity platforms to create, update, deactivate, and list users. It can be used alongside SSO, but it does not depend on SSO.

```ruby
gem "better_auth-scim"
```

```ruby
require "better_auth"
require "better_auth/scim"

BetterAuth.auth(
  plugins: [
    BetterAuth::Plugins.scim(
      store_scim_token: "hashed",
      provider_ownership: { enabled: true }
    )
  ]
)
```

Implemented API methods include token generation, provider connection management, SCIM user CRUD, and SCIM metadata endpoints:

- `generate_scim_token`
- `list_scim_provider_connections`
- `get_scim_provider_connection`
- `delete_scim_provider_connection`
- `create_scim_user`
- `list_scim_users`
- `get_scim_user`
- `update_scim_user`
- `patch_scim_user`
- `delete_scim_user`
- `get_scim_service_provider_config`
- `get_scim_schemas`
- `get_scim_schema`
- `get_scim_resource_types`
- `get_scim_resource_type`

Options use Ruby snake_case names: `store_scim_token`, `default_scim`, `provider_ownership`, `required_role`, `before_scim_token_generated`, and `after_scim_token_generated`.

The plugin exposes upstream-style surface metadata:

- `BetterAuth::Plugins.scim.version` returns the gem SCIM version.
- `BetterAuth::Plugins.scim.client` returns the Ruby client-plugin descriptor (`scim-client`) for integrations that inspect plugin parity metadata.
- SCIM protocol routes are hidden from generated OpenAPI output, matching upstream `HIDE_METADATA`; provider management routes remain visible.
