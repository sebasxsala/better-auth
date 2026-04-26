# Feature: Last Login Method Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/last-login-method/index.ts`, `upstream/packages/better-auth/src/plugins/last-login-method/last-login-method.test.ts`, `upstream/packages/better-auth/src/plugins/last-login-method/custom-prefix.test.ts`

## Summary

Tracks the most recent successful login method through a readable cookie and optional user-table field.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.last_login_method`.
- Supports `cookie_name`, `max_age`, `custom_resolve_method`, and `store_in_database`.
- Stores `lastLoginMethod` in the user schema when database storage is enabled.
- Resolves email, social callback, OAuth2 callback, SIWE, and passkey route patterns.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/last_login_method_test.rb
```
