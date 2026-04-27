# Feature: Generic OAuth Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/generic-oauth/index.ts`, `upstream/packages/better-auth/src/plugins/generic-oauth/routes.ts`, `upstream/packages/better-auth/src/plugins/generic-oauth/generic-oauth.test.ts`

## Summary

Adds OAuth2 sign-in and account linking for custom providers.

**Status:** Complete for Ruby server parity.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.generic_oauth`.
- Adds `/sign-in/oauth2`, `/oauth2/callback/:providerId`, and `/oauth2/link`.
- Supports configured provider IDs, authorization URLs, token URLs, issuer checks, scopes, PKCE state generation, DB-backed and cookie-backed state strategies with mismatch cleanup, dynamic authorization params, `response_mode`, custom token exchange, custom token failure redirects, custom user-info lookup, standard HTTP token/userinfo exchange, account-info/refresh integration through the social-provider map, encrypted OAuth token storage, account cookies, user mapping, implicit sign-up controls, and account linking.
- Provides Ruby helper factories for Auth0, Gumroad, HubSpot, Keycloak, LINE, Microsoft Entra ID, Okta, Patreon, and Slack.
- Stores provider accounts in the core `account` table and creates regular Better Auth sessions.

## Key Differences

- Ruby options use snake_case equivalents of upstream camelCase.
- Tests use `get_token` and `get_user_info` callables to avoid network-dependent OAuth servers while preserving endpoint behavior.
- Standard token and user-info HTTP fallback uses stdlib `Net::HTTP`; it supports custom token headers, Basic/Post client authentication, extra token params, token expiry normalization, and OIDC-style userinfo mapping.
- Browser client aliases and TypeScript async typing are outside Ruby server scope.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/generic_oauth_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/generic_oauth_test.rb`
