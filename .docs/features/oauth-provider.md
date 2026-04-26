# Feature: OAuth Provider Plugin

**Upstream Reference:** `upstream/packages/oauth-provider/src/index.ts`, `upstream/packages/oauth-provider/src/oauth.ts`, `upstream/packages/oauth-provider/src/metadata.ts`, `upstream/packages/oauth-provider/src/token.ts`, `upstream/packages/oauth-provider/src/introspect.ts`, `upstream/packages/oauth-provider/src/revoke.ts`, `upstream/packages/oauth-provider/src/oauthClient/endpoints.ts`, `upstream/packages/oauth-provider/src/oauthConsent/endpoints.ts`, and matching `*.test.ts` files.

## Summary

Ports the separate upstream OAuth provider package into the Ruby core plugin namespace for metadata, client registration/lookup, authorization-code consent flow, client credentials tokens, introspection, revocation, and userinfo support.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.oauth_provider`.
- Adds `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/consent`, `/oauth2/register`, `/oauth2/client`, `/oauth2/client/:id`, `/oauth2/clients`, `/oauth2/token`, `/oauth2/introspect`, `/oauth2/revoke`, and `/oauth2/userinfo`.
- Adds `oauthClient`, `oauthRefreshToken`, `oauthAccessToken`, and `oauthConsent` schema entries.
- Implements upstream-style issuer normalization for RFC 9207: non-local HTTP issuers normalize to HTTPS, query/fragment are stripped, and localhost HTTP remains allowed.

## Key Differences

- The Ruby port now implements the core metadata surface, dynamic client management, authorization-code consent flow, client-credentials flow, introspection, revocation, and userinfo. Organization reference, logout, encrypted client-secret variants, and deeper rate-limit matrices remain future polish.
- Array/json schema fields are stored natively by the memory adapter. SQL-specific encoding remains documented as an adapter concern for later hardening.
- No new dependency was added.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/oauth_provider_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/oauth_provider_test.rb`
