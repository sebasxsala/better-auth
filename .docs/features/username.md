# Feature: Username Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/username/index.ts`, `upstream/packages/better-auth/src/plugins/username/schema.ts`, `upstream/packages/better-auth/src/plugins/username/username.test.ts`

## Summary

Adds username fields to users, mirrors username data into email sign-up and update-user flows, exposes username/password sign-in, and exposes username availability checks.
The demo-level Rack flow is covered end to end through `/sign-up/email`, `/sign-in/username`, and `/get-session`.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.username`.
- Adds `username` and `displayUsername` to the user schema.
- Uses plugin database hooks to normalize username and display username on create/update.
- Uses plugin before hooks for `/sign-up/email` and `/update-user` validation and duplicate checks.
- Adds `/sign-in/username` and `/is-username-available` endpoints.

## Key Differences

- The Ruby memory adapter does not enforce unique schema fields globally yet, so the username hook checks duplicates against the normalized stored username before user creation/update. SQL adapters still receive `unique: true` from the schema.
- Ruby options are idiomatic snake_case: `min_username_length`, `username_normalization`, `display_username_validator`, and `validation_order`.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/username_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/username_test.rb`
