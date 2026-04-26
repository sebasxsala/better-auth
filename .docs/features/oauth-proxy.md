# Feature: OAuth Proxy Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/oauth-proxy/index.ts`, `upstream/packages/better-auth/src/plugins/oauth-proxy/oauth-proxy.test.ts`

## Summary

Adds OAuth callback proxy support for preview/current URLs that differ from the production OAuth callback origin.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.oauth_proxy`.
- Adds `/oauth-proxy-callback`.
- Adds hooks around `/sign-in/social`, `/sign-in/oauth2`, `/callback/:providerId`, and `/oauth2/callback/:providerId`.
- Rewrites callback URLs to the current URL, unwraps same-origin proxy redirects, and appends encrypted cookie payloads for cross-origin proxy redirects.
- Validates the proxy `callbackURL` against trusted origins, allowing safe relative paths.
- Decrypts cookie payloads, rejects expired/future/malformed payloads, sets cookies, and redirects to the original callback URL.

## Key Differences

- Uses core `BetterAuth::Crypto.symmetric_encrypt` and `symmetric_decrypt`; no new dependency was added.
- This port covers the server redirect/cookie proxy mechanics. The deeper upstream stateless state-cookie package restoration is represented by encrypted callback and cookie behavior, while exact internal OAuth state-cookie emulation remains future polish if DB-less provider flows need it.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/oauth_proxy_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/oauth_proxy_test.rb`
