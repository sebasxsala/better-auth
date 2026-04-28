# Feature: SSO Plugin

**Upstream Reference:** `upstream/packages/sso/src/index.ts`, `upstream/packages/sso/src/routes/sso.ts`, `upstream/packages/sso/src/routes/providers.ts`, `upstream/packages/sso/src/routes/domain-verification.ts`, `upstream/packages/sso/src/oidc/`, `upstream/packages/sso/src/saml/`, `upstream/packages/sso/src/linking/org-assignment.ts`

## Summary

Adds a Ruby server-side SSO plugin as `BetterAuth::Plugins.sso` with provider CRUD, OIDC sign-in/callback, SAML sign-in/callback/ACS, SP metadata, domain verification, and SAML callback origin bypass paths.

Status: Complete for Ruby server parity when SAML apps opt into `better_auth-saml`.

## Ruby Adaptation

- Implemented inside the core gem for provider lifecycle and route handling, with optional real SAML XML validation in `packages/better_auth-saml`.
- Adds `ssoProvider` schema fields: `issuer`, `oidcConfig`, `samlConfig`, `userId`, `providerId`, `domain`, `domainVerified`, `domainVerificationToken`, and `organizationId`.
- Adds `/sso/register`, `/sign-in/sso`, `/sso/callback/:providerId`, `/sso/saml2/callback/:providerId`, `/sso/saml2/sp/acs/:providerId`, `/sso/saml2/sp/metadata`, `/sso/providers`, `/sso/providers/:providerId`, `/sso/request-domain-verification`, and `/sso/verify-domain`.
- Supports injected OIDC token/user callbacks in provider config, a dependency-free SAML test payload format for core coverage, optional SAML AuthnRequest/parser/validation hooks, and verified-domain organization membership assignment when the organization plugin is enabled.
- Configures origin-check bypass only for upstream SAML callback/ACS paths because those POSTs come from external IdPs.
- Sanitizes provider read responses with upstream-style OIDC client-id masking and SAML certificate parse results.
- Hydrates OIDC discovery documents, validates trusted discovered URLs, resolves relative endpoints, preserves configured values, and selects token endpoint auth methods.
- Enforces provider access for user-owned providers and organization admin/owner providers.
- Covers SAML RelayState safety, replay protection, AuthnRequest/parser/validator adapter contracts, XML assertion count validation, and signature-algorithm policy decisions.
- `better_auth-saml` depends on `ruby-saml >= 1.18.1` and validates signed XML assertions, IdP certificates, forged/tampered responses, assertion count, XSW-style wrapping, destination/recipient/audience/issuer/timestamps, and deprecated/unknown signature algorithms. Encrypted assertion handling is delegated to `ruby-saml` when `spPrivateKey` and `spCertificate` are configured in `samlConfig`.

## Key Differences

- Core SAML cryptographic signature verification and decryption are intentionally not bundled into `better_auth`; apps opt into `better_auth-saml`, which depends on `ruby-saml >= 1.18.1` and plugs into the core `auth_request_url` and `parse_response` hooks.
- Without `better_auth-saml`, core SSO still exposes the adapter hook contract and remains dependency-free for apps that use only OIDC SSO or custom SAML validators.
- Organization auto-assignment covers verified SSO provider domains with the Ruby organization plugin.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_oidc_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_saml_test.rb
cd ../better_auth-saml
rbenv exec bundle exec ruby -Itest test/better_auth/saml_test.rb
```
