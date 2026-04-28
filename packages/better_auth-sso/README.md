# Better Auth SSO

External SSO plugin package for `better_auth`.

SSO is the app-facing feature. It supports OIDC SSO and SAML SSO. SAML is not the same thing as SSO; SAML is one protocol used by SSO.

```ruby
require "better_auth"
require "better_auth/sso"

BetterAuth.auth(
  plugins: [
    BetterAuth::Plugins.sso
  ]
)
```

SAML XML validation is included in this package and backed by `ruby-saml`:

```ruby
require "better_auth/sso"

BetterAuth.auth(
  plugins: [
    BetterAuth::Plugins.sso(
      BetterAuth::SSO::SAMLHooks.merge_options(
        {},
        BetterAuth::SSO::SAML.sso_options
      )
    )
  ]
)
```

SCIM is a separate provisioning feature and lives in `better_auth-scim`.
