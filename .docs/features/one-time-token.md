# Feature: One-Time Token Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/one-time-token/index.ts`, `upstream/packages/better-auth/src/plugins/one-time-token/utils.ts`, `upstream/packages/better-auth/src/plugins/one-time-token/one-time-token.test.ts`

## Summary

Adds one-time session tokens that can be generated from an existing session and consumed once to recover that session.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.one_time_token`.
- Adds `/one-time-token/generate` and `/one-time-token/verify`.
- Stores one-time tokens in the core `verification` table with `one-time-token:<stored-token>` identifiers.
- Supports `expires_in`, `disable_client_request`, `generate_token`, `disable_set_session_cookie`, `store_token`, and `set_ott_header_on_new_session`.

## Key Differences

- Ruby options use snake_case equivalents of upstream camelCase options.
- Hashed token storage uses `BetterAuth::Crypto.sha256(..., encoding: :base64url)`, matching upstream's SHA-256/base64url storage behavior.
- Rack GET requests without bodies now safely parse as an empty body; the one-time-token Rack test covers this router behavior.
- Ruby exposes server methods as snake_case (`generate_one_time_token`, `verify_one_time_token`) instead of the upstream client aliases; TypeScript client alias parity is outside the Ruby server surface.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/one_time_token_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/one_time_token_test.rb`
