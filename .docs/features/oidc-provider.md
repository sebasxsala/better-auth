# Feature: OIDC Provider Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/oidc-provider/index.ts`, `upstream/packages/better-auth/src/plugins/oidc-provider/authorize.ts`, `upstream/packages/better-auth/src/plugins/oidc-provider/schema.ts`, `upstream/packages/better-auth/src/plugins/oidc-provider/oidc.test.ts`, `upstream/packages/better-auth/src/plugins/oidc-provider/utils/prompt.test.ts`

## Summary

Adds OIDC provider metadata, dynamic client registration, authorization-code issuance, token exchange, refresh tokens, userinfo, prompt parsing, consent-code flow, and RP-initiated logout.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.oidc_provider`.
- Adds `/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/consent`, `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/register`, `/oauth2/client/:id`, and `/oauth2/endsession`.
- Adds `oauthApplication`, `oauthAccessToken`, and `oauthConsent` schema tables.
- Uses existing `JWT`/OpenSSL/stdlib helpers only; no new runtime dependency was added.
- Stores short-lived authorization codes and issued token lookup state in the plugin runtime store while also persisting token/client records through the configured adapter.

## Key Differences

- Ruby options use snake_case equivalents of upstream camelCase.
- Current coverage focuses on server-side Rack/API behavior: metadata, prompt validation, client registration, consent redirects, auth-code redirect, token exchange, userinfo, refresh-token issuance, and logout.
- Full upstream consent-screen UI rendering, JWT plugin algorithm negotiation, encrypted client-secret variants, and exhaustive prompt/max-age matrices remain future polish.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/oidc_provider_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/oidc_provider_test.rb`
