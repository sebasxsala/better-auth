# Feature: Additional Fields Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/additional-fields/additional-fields.test.ts`, `upstream/packages/better-auth/src/plugins/additional-fields/client.ts`

## Summary

Adds plugin-style schema inference for extra `user` and `session` fields while reusing the core schema/adapter default-value behavior.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.additional_fields`.
- Merges user/session fields into plugin schema and into configuration defaults.
- Route behavior is exercised through sign-up, update-user, update-session, and get-session endpoints.
- Ruby filters input to declared additional fields, applies defaults, rejects `input: false`, and refreshes session cookies after user/session updates.
- Upstream `inferAdditionalFields` is TypeScript client inference only; Ruby has no typed browser client, so that client-only surface is intentionally out of scope.

## Testing

```bash
cd packages/better_auth
rbenv exec ruby -Ilib -Itest test/better_auth/plugins/additional_fields_test.rb
```
