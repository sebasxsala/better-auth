# Feature: OAuth Provider Plugin

**Upstream Reference:** `upstream/packages/oauth-provider/src/index.ts`, `upstream/packages/oauth-provider/src/oauth.ts`, `upstream/packages/oauth-provider/src/metadata.ts`, `upstream/packages/oauth-provider/src/token.ts`, `upstream/packages/oauth-provider/src/introspect.ts`, `upstream/packages/oauth-provider/src/revoke.ts`, `upstream/packages/oauth-provider/src/oauthClient/endpoints.ts`, `upstream/packages/oauth-provider/src/oauthConsent/endpoints.ts`, and matching `*.test.ts` files.

## Summary

Ports the separate upstream OAuth provider package into the Ruby `better_auth-oauth-provider` package for metadata, client registration/lookup, authorization-code consent flow, client credentials tokens, introspection, revocation, and userinfo support.

Status: Extracted to `better_auth-oauth-provider`.

## Package Boundary

Upstream ships OAuth provider as `@better-auth/oauth-provider`, not from core `better-auth/plugins`. Ruby exposes this as `better_auth-oauth-provider`.

This is separate from OIDC provider. OIDC provider currently ships from upstream core plugin exports and should remain in `better_auth` unless upstream changes.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.oauth_provider` after `require "better_auth/oauth_provider"`.
- Adds `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/consent`, `/oauth2/register`, `/oauth2/client`, `/oauth2/client/:id`, `/oauth2/clients`, `/oauth2/token`, `/oauth2/introspect`, `/oauth2/revoke`, and `/oauth2/userinfo`.
- Adds `oauthClient`, `oauthRefreshToken`, `oauthAccessToken`, and `oauthConsent` schema entries.
- Implements upstream-style issuer normalization for RFC 9207: non-local HTTP issuers normalize to HTTPS, query/fragment are stripped, and localhost HTTP remains allowed.

## Key Differences

- The Ruby port now implements the core metadata surface, dynamic client management, authorization-code consent flow, client-credentials flow, introspection, revocation, and userinfo in `packages/better_auth-oauth-provider`. Organization reference, logout, encrypted client-secret variants, and deeper rate-limit matrices remain future polish.
- Array/json schema fields are stored natively by the memory adapter. SQL-specific encoding remains documented as an adapter concern for later hardening.
- No new dependency was added.

## Testing

```bash
cd packages/better_auth-oauth-provider
rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb
```

Key test file:

- `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`
