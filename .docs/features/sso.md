# Feature: SSO Plugin

**Upstream Reference:** `upstream/packages/sso/src/index.ts`, `upstream/packages/sso/src/routes/sso.ts`, `upstream/packages/sso/src/routes/providers.ts`, `upstream/packages/sso/src/routes/domain-verification.ts`, `upstream/packages/sso/src/oidc/`, `upstream/packages/sso/src/saml/`, `upstream/packages/sso/src/linking/org-assignment.ts`

## Summary

Adds a Ruby server-side SSO plugin as `BetterAuth::Plugins.sso` with provider CRUD, OIDC sign-in/callback, SAML sign-in/callback/ACS, SP metadata, domain verification, and SAML callback origin bypass paths.

Status: Extracted to `better_auth-sso`; SAML XML validation lives inside `better_auth-sso` through its package-owned `ruby-saml` dependency.

## Package Boundary

SSO is the app-facing plugin. SAML is only one protocol inside SSO, and OIDC is another protocol inside SSO. To match upstream `@better-auth/sso`, Ruby SSO lives in `better_auth-sso`.

SAML is protocol support within `better_auth-sso`, not its own package boundary. Ruby uses `ruby-saml` inside the SSO gem for signed XML validation because that maps to upstream's `packages/sso/src/saml/` layout.

## Ruby Adaptation

- Implemented in `packages/better_auth-sso` for provider lifecycle, route handling, OIDC, and real SAML XML validation.
- Adds `ssoProvider` schema fields: `issuer`, `oidcConfig`, `samlConfig`, `userId`, `providerId`, `domain`, `domainVerified`, `domainVerificationToken`, and `organizationId`.
- Adds `/sso/register`, `/sign-in/sso`, `/sso/callback/:providerId`, `/sso/saml2/callback/:providerId`, `/sso/saml2/sp/acs/:providerId`, `/sso/saml2/sp/metadata`, `/sso/saml2/sp/slo/:providerId`, `/sso/saml2/logout/:providerId`, `/sso/providers`, `/sso/providers/:providerId`, `/sso/request-domain-verification`, and `/sso/verify-domain`.
- Supports injected OIDC token/user callbacks in provider config, a dependency-free SAML test payload format for core coverage, optional SAML AuthnRequest/parser/validation hooks, and verified-domain organization membership assignment when the organization plugin is enabled.
- Configures origin-check bypass only for upstream SAML callback/ACS paths because those POSTs come from external IdPs.
- Sanitizes provider read responses with upstream-style OIDC client-id masking and SAML certificate parse results.
- Hydrates OIDC discovery documents, validates trusted discovered URLs, resolves relative endpoints, preserves configured values, and selects token endpoint auth methods.
- Enforces provider access for user-owned providers and organization admin/owner providers.
- Covers SAML RelayState safety, replay protection, AuthnRequest/parser/validator adapter contracts, XML assertion count validation, and signature-algorithm policy decisions.
- Supports SAML Single Logout when `saml.enableSingleLogout` / `saml[:enable_single_logout]` is enabled. ACS stores `NameID`/`SessionIndex` session lookup records, IdP LogoutRequest revokes matching Better Auth sessions, SP-initiated logout creates a pending logout request, and LogoutResponse consumes that pending record.
- `better_auth-sso` depends on `ruby-saml >= 1.18.1` and validates signed XML assertions, IdP certificates, forged/tampered responses, assertion count, XSW-style wrapping, destination/recipient/audience/issuer/timestamps, and deprecated/unknown signature algorithms. Encrypted assertion handling is delegated to `ruby-saml` when `spPrivateKey` and `spCertificate` are configured in `samlConfig`.

## Key Differences

- SAML cryptographic signature verification and decryption are intentionally not bundled into `better_auth`; they live in `better_auth-sso`, matching upstream `@better-auth/sso`.
- `better_auth-sso` still exposes the adapter hook contract for custom SAML validators, but the package includes the default `ruby-saml` integration.
- Organization auto-assignment covers verified SSO provider domains with the Ruby organization plugin.

## Testing

```bash
cd packages/better_auth
cd ../better_auth-sso
rbenv exec bundle exec ruby -Itest test/better_auth/sso_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/sso_oidc_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/sso_saml_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/sso_ruby_saml_test.rb
```
