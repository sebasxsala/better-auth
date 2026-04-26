# Feature: Custom Session Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/custom-session/index.ts`, `upstream/packages/better-auth/src/plugins/custom-session/custom-session.test.ts`

## Summary

Overrides `/get-session` with caller-defined session shaping and can mutate multi-session device-list entries.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.custom_session`.
- The resolver receives `{ session:, user: }` and the endpoint context.
- Session cookies are preserved when wrapping get-session.
- `should_mutate_list_device_sessions_endpoint` maps to the upstream option.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/custom_session_test.rb
```
