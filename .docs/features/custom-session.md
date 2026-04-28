# Feature: Custom Session Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/custom-session/index.ts`, `upstream/packages/better-auth/src/plugins/custom-session/custom-session.test.ts`

## Summary

Overrides `/get-session` with caller-defined session shaping and can mutate multi-session device-list entries.

**Status:** Complete for Ruby server parity.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.custom_session`.
- The resolver receives the same parsed `{ session:, user: }` payload as the normal `/get-session` response plus the endpoint context, so fields marked `returned: false` stay hidden.
- Session cookies are preserved when wrapping get-session.
- `should_mutate_list_device_sessions_endpoint` maps to the upstream option.
- Unauthenticated session lookup returns `nil` without invoking the resolver.
- The replacement endpoint carries OpenAPI metadata for the custom-session route.
- TypeScript inference and upstream memory-leak instrumentation are outside Ruby runtime scope.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/custom_session_test.rb
```
