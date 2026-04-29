# Better Auth SCIM

External SCIM provisioning plugin package for `better_auth`.

SCIM is not login. It is a provisioning API used by identity platforms to create, update, deactivate, and list users. It can be used alongside SSO, but it does not depend on SSO.

```ruby
require "better_auth"
require "better_auth/scim"

BetterAuth.auth(
  plugins: [
    BetterAuth::Plugins.scim
  ]
)
```

## Provider Management

The Ruby package exposes the upstream SCIM management routes:

- `POST /scim/generate-token`
- `GET /scim/list-provider-connections`
- `GET /scim/get-provider-connection`
- `POST /scim/delete-provider-connection`

Organization-scoped token generation requires the organization plugin and a privileged role. By default `admin` and the organization creator role (`owner` unless configured otherwise) can generate and manage organization SCIM providers; regular members are denied with `Insufficient role for this operation`.

Set `provider_ownership: {enabled: true}` to bind non-organization providers to the user that generated them. Owned personal providers can only be listed, fetched, regenerated, or deleted by their owner. Legacy providers without `userId` remain visible to preserve compatibility.
