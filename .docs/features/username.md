# Feature: Username Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/username/index.ts`, `upstream/packages/better-auth/src/plugins/username/schema.ts`, `upstream/packages/better-auth/src/plugins/username/username.test.ts`

## Summary

Adds username fields to users, mirrors username data into email sign-up and update-user flows, exposes username/password sign-in, and exposes username availability checks.
The demo-level Rack flow is covered end to end through `/sign-up/email`, `/sign-in/username`, and `/get-session`.
Ruby tests cover the upstream runtime matrix for sign-up/sign-in, availability, normalization, display username mirroring and preservation, custom display username validation, validation-order behavior, duplicate sign-up/update semantics, same-user update allowance, custom username validators, and email-verification no-leak behavior.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.username`.
- Adds `username` and `displayUsername` to the user schema.
- Uses plugin database hooks to normalize username and display username on create/update.
- Uses plugin before hooks for `/sign-up/email` and `/update-user` validation and duplicate checks.
- Adds `/sign-in/username` and `/is-username-available` endpoints.
- Returns upstream-compatible duplicate semantics: duplicate sign-up is `422`, while conflicting update-user remains `400`.

## Key Differences

- The Ruby memory adapter does not enforce unique schema fields globally yet, so the username hook checks duplicates against the normalized stored username before user creation/update. SQL adapters receive `unique: true` from the schema for adapter-level uniqueness.
- Ruby options are idiomatic snake_case: `min_username_length`, `username_normalization`, `display_username_validator`, and `validation_order`.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/username_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/username_test.rb`
