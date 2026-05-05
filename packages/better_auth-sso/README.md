# Better Auth SSO

External SSO plugin package for `better_auth`.

SSO is the app-facing feature. It supports OIDC SSO, SAML SSO, provider management,
domain verification, SAML replay protection, runtime OIDC discovery, organization
assignment, and SAML Single Logout. SAML is not the same thing as SSO; SAML is
one protocol used by SSO.

```ruby
require "better_auth"
require "better_auth/sso"

BetterAuth.auth(
  plugins: [
    BetterAuth::Plugins.sso
  ]
)
```

SAML XML validation is included in this package and backed by `ruby-saml`.
Production XML SAML deployments should configure `BetterAuth::SSO::SAML.sso_options`
or compatible SAML hooks so AuthnRequest generation and SAMLResponse parsing use
the real XML/SAML boundary instead of the lightweight JSON/base64 fallback used by
local tests:

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

## SAML Single Logout

SAML SLO follows upstream route shapes when `saml.enableSingleLogout` is enabled:

- `POST /sso/saml2/logout/:providerId` starts SP-initiated logout for the current session.
- `GET|POST /sso/saml2/sp/slo/:providerId` handles IdP LogoutRequest and LogoutResponse payloads.
- ACS stores SAML `NameID` and `SessionIndex` lookup records so IdP-initiated logout can revoke the matching Better Auth session.

Ruby keeps the lightweight JSON/base64 fallback used by the local SAML test adapter, and real XML deployments should configure `BetterAuth::SSO::SAML.sso_options` or compatible SAML hooks.

SCIM is a separate provisioning feature and lives in `better_auth-scim`.

## Organization Assignment

When the organization plugin is installed, SSO can add users to an organization
linked to an SSO provider. SSO login flows assign from the matched provider.
Generic OAuth callbacks under `/callback/:provider` also assign by verified SSO
email domain when domain verification is enabled, matching upstream behavior for
users who sign in through non-SSO OAuth but share an enterprise domain.

## Schema Compatibility

The Ruby package intentionally keeps the historical default SSO provider model
name `ssoProviders` for backward compatibility. Upstream Better Auth defaults to
`ssoProvider`; configure `model_name:` if your application needs a different
storage model name.

Field mapping options are supported through `fields:` for the SSO provider
schema, including `issuer`, `oidcConfig`, `samlConfig`, `userId`, `providerId`,
`organizationId`, `domain`, and `domainVerified`.

## Scope and Non-Goals

This package does not currently imply support for advanced enterprise features
such as `private_key_jwt`, mTLS client authentication, every SAML XML edge case,
or large internal SSO refactors. Those items are tracked in the
[upstream and product alignment backlog](../../.docs/backlog/upstream-product-alignment.md)
until they have explicit product scope and upstream parity decisions.
