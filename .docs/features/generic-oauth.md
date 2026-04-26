# Feature: Generic OAuth Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/generic-oauth/index.ts`, `upstream/packages/better-auth/src/plugins/generic-oauth/routes.ts`, `upstream/packages/better-auth/src/plugins/generic-oauth/generic-oauth.test.ts`

## Summary

Adds OAuth2 sign-in and account linking for custom providers.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.generic_oauth`.
- Adds `/sign-in/oauth2`, `/oauth2/callback/:providerId`, and `/oauth2/link`.
- Supports configured provider IDs, authorization URLs, token URLs, issuer checks, scopes, PKCE state generation, custom token exchange, custom user-info lookup, user mapping, implicit sign-up controls, and account linking.
- Stores provider accounts in the core `account` table and creates regular Better Auth sessions.

## Key Differences

- Ruby options use snake_case equivalents of upstream camelCase.
- Tests use `get_token` and `get_user_info` callables to avoid network-dependent OAuth servers while preserving endpoint behavior.
- Standard token and user-info HTTP fallback uses stdlib `Net::HTTP`; provider helper factories like Okta/Auth0/Slack are not ported yet.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/generic_oauth_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/generic_oauth_test.rb`
