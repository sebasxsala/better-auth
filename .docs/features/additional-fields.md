# Feature: Additional Fields Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/additional-fields/additional-fields.test.ts`, `upstream/packages/better-auth/src/plugins/additional-fields/client.ts`

## Summary

Adds plugin-style schema inference for extra `user` and `session` fields while reusing the core schema/adapter default-value behavior.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.additional_fields`.
- Merges user/session fields into plugin schema and into configuration defaults.
- Route behavior is exercised through existing sign-up, update-user, and get-session endpoints.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/additional_fields_test.rb
```
