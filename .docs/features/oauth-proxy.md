# Feature: OAuth Proxy Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/oauth-proxy/index.ts`, `upstream/packages/better-auth/src/plugins/oauth-proxy/oauth-proxy.test.ts`

## Summary

Adds OAuth callback proxy support for preview/current URLs that differ from the production OAuth callback origin.

Status: Complete for Ruby server parity.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.oauth_proxy`.
- Adds `/oauth-proxy-callback`.
- Adds hooks around `/sign-in/social`, `/sign-in/oauth2`, `/callback/:providerId`, and `/oauth2/callback/:providerId`.
- Rewrites callback URLs to the current URL, unwraps same-origin proxy redirects, and appends encrypted cookie payloads for cross-origin proxy redirects.
- Validates the proxy `callbackURL` against trusted origins, allowing safe relative paths.
- Decrypts cookie payloads, rejects expired/future/malformed payloads, sets cookies, and redirects to the original callback URL.
- In stateless cookie-state OAuth flows, encrypts the original state plus OAuth state cookie into the provider `state` parameter and restores the cookie before callback validation, enabling DB-less provider callbacks.

## Key Differences

- Uses core `BetterAuth::Crypto.symmetric_encrypt` and `symmetric_decrypt`; no new dependency was added.
- Uses Ruby's Rack endpoint and hook pipeline rather than upstream middleware internals, while preserving the server-visible redirect, cookie, timestamp, trusted-callback, and stateless state-package behavior.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/oauth_proxy_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/oauth_proxy_test.rb`
