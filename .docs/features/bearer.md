# Feature: Bearer Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/bearer/index.ts`, `upstream/packages/better-auth/src/plugins/bearer/bearer.test.ts`

## Summary

Allows session lookup from an `Authorization: Bearer ...` header and exposes newly issued signed session tokens through `set-auth-token`.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.bearer`.
- Accepts signed tokens and, unless `require_signature` is true, raw session tokens that are signed into the request cookie context.
- Adds `set-auth-token` and `Access-Control-Expose-Headers` when a session cookie is issued.
- Allows `get_session` and `list_sessions` through `Authorization: Bearer ...` headers.
- Preserves an existing valid session cookie when the authorization header contains an invalid bearer token.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/bearer_test.rb
```
