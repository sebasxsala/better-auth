# Feature: Last Login Method Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/last-login-method/index.ts`, `upstream/packages/better-auth/src/plugins/last-login-method/last-login-method.test.ts`, `upstream/packages/better-auth/src/plugins/last-login-method/custom-prefix.test.ts`

## Summary

Tracks the most recent successful login method through a readable cookie and optional user-table field.

Status: Complete for Ruby server parity.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.last_login_method`.
- Supports `cookie_name`, `max_age`, `custom_resolve_method`, and `store_in_database`.
- Stores `lastLoginMethod` in the user schema when database storage is enabled.
- Resolves email, social callback, OAuth2 callback, magic-link verify, SIWE, and passkey route patterns.
- Uses upstream's `lastLoginMethod` default storage field name when database storage is enabled.
- Normalizes missing hook paths to an empty string before calling `custom_resolve_method`.
- Updates the cookie and database value on subsequent successful logins.
- Suppresses cookie/database updates for failed email and OAuth callbacks.
- Preserves exact custom cookie names even when `advanced.cookie_prefix` is configured, and inherits cross-subdomain/cross-origin/default cookie attributes from the core cookie configuration.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/last_login_method_test.rb
```
