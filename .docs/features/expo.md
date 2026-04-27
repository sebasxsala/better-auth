# Feature: Expo Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/expo/src/index.ts`, `upstream/packages/expo/src/routes.ts`, `upstream/packages/expo/test/expo.test.ts`, `upstream/packages/expo/test/last-login-method.test.ts`

## Summary

Adds server-side Expo/mobile support through `BetterAuth::Plugins.expo`: authorization proxy cookies, `expo-origin` request handling, development trusted origin defaults, and deep-link cookie transfer.

## Ruby Adaptation

- Implemented inside the core gem as a plugin.
- Adds `/expo-authorization-proxy`.
- Sets signed `state` cookies or temporary `oauth_state` cookies before redirecting to the provider authorization URL.
- Uses `expo-origin` as `Origin` when the request lacks a regular origin and `disable_origin_override` is not enabled.
- Preserves a regular `Origin` header when present.
- Adds `exp://` to trusted origins through plugin init.
- Injects `Set-Cookie` into trusted non-HTTP deep-link redirects for callback, OAuth2 callback, magic-link verify, and verify-email paths, including wildcard trusted origins.

## Key Differences

- React Native storage, focus manager, online manager, and browser-opening client behavior are client-only and out of Ruby server scope.
- The core router allows some no-cookie POSTs without an Origin header; `disable_origin_override` therefore preserves core behavior rather than forcing a rejection.
- Server-side Expo works with the Ruby Rack surface because it only depends on request origin rewriting, trusted-origin checks, temporary auth cookies, and redirect hook handling; native secure storage remains the Expo client package's responsibility.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/expo_test.rb
```
