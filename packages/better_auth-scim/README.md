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
