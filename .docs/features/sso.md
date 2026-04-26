# Feature: SSO Plugin

**Upstream Reference:** `upstream/packages/sso/src/index.ts`, `upstream/packages/sso/src/routes/sso.ts`, `upstream/packages/sso/src/routes/providers.ts`, `upstream/packages/sso/src/routes/domain-verification.ts`, `upstream/packages/sso/src/oidc/`, `upstream/packages/sso/src/saml/`, `upstream/packages/sso/src/linking/org-assignment.ts`

## Summary

Adds a first Ruby server-side SSO plugin as `BetterAuth::Plugins.sso` with provider CRUD, OIDC sign-in/callback, SAML sign-in/callback/ACS, SP metadata, domain verification, and SAML callback origin bypass paths.

## Ruby Adaptation

- Implemented inside the core gem rather than a separate Ruby gem for this phase.
- Adds `ssoProvider` schema fields: `issuer`, `oidcConfig`, `samlConfig`, `userId`, `providerId`, `domain`, `domainVerified`, `domainVerificationToken`, and `organizationId`.
- Adds `/sso/register`, `/sign-in/sso`, `/sso/callback/:providerId`, `/sso/saml2/callback/:providerId`, `/sso/saml2/sp/acs/:providerId`, `/sso/saml2/sp/metadata`, `/sso/providers`, `/sso/providers/:providerId`, `/sso/request-domain-verification`, and `/sso/verify-domain`.
- Supports injected OIDC token/user callbacks in provider config, a dependency-free SAML test payload format for current Ruby coverage, optional SAML response validation hooks, and verified-domain organization membership assignment when the organization plugin is enabled.
- Configures origin-check bypass only for upstream SAML callback/ACS paths because those POSTs come from external IdPs.

## Key Differences

- Full XML signature, assertion, encryption, and metadata parsing remains future polish unless a SAML dependency is approved.
- Organization auto-assignment now covers verified SSO provider domains with the Ruby organization plugin; advanced upstream provisioning policies remain future polish.
- OIDC discovery has a focused helper with injectable fetch for tests; full runtime HTTP matrix remains partial.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_oidc_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_saml_test.rb
```
