# Feature: Multi Session Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/multi-session/index.ts`, `upstream/packages/better-auth/src/plugins/multi-session/multi-session.test.ts`

## Summary

Stores signed per-session cookies so one browser can switch between multiple active user sessions.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.multi_session`.
- Implements `/multi-session/list-device-sessions`, `/multi-session/set-active`, and `/multi-session/revoke`.
- Adds and clears `*_multi-<token>` cookies through after hooks.
- Enforces the upstream `INVALID_SESSION_TOKEN` error code.
- Allows set-active with only a valid signed multi-session cookie, requires an active session for revoke, replaces old same-user multi-session cookies before enforcing `maximum_sessions`, and moves the active session to the next non-expired valid device session when revoked.
- Only creates multi-session cookies for responses that actually set a session cookie, and only clears signed multi-session cookies during sign-out.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/multi_session_test.rb
```
