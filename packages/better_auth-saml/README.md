# Better Auth SAML

Optional SAML XML validation companion for `better_auth`.

This package depends on `ruby-saml >= 1.18.1` and wires real SAML AuthnRequest generation plus response parsing into the core SSO plugin through adapter hooks. Apps that do not use SAML do not need to install this package.

```ruby
require "better_auth"
require "better_auth/saml"

BetterAuth.auth(
  plugins: [
    BetterAuth::Plugins.sso(
      BetterAuth::SAML.sso_options
    )
  ]
)
```

The core `better_auth` gem still owns provider CRUD, RelayState handling, replay protection, sessions, and organization assignment. This package generates the outbound SAML AuthnRequest URL and validates/maps the incoming SAML response before core SSO creates the Better Auth session.

The validator checks signed assertions with the configured IdP certificate, rejects unsigned/forged/tampered/XSW responses, rejects multiple or missing assertions, validates audience/recipient/destination/issuer/timestamps, and rejects deprecated SHA1 signatures by default. Encrypted assertions are handled by `ruby-saml` when the provider `samlConfig` includes `spPrivateKey` and `spCertificate`.
