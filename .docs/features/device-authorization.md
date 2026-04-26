# Feature: Device Authorization Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/device-authorization/index.ts`, `upstream/packages/better-auth/src/plugins/device-authorization/routes.ts`, `upstream/packages/better-auth/src/plugins/device-authorization/schema.ts`, `upstream/packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts`

## Summary

Adds OAuth 2.0 device authorization flow support: device/user code issuance, polling, verification, approval, denial, expiration, slow-down handling, and custom client/URI hooks.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.device_authorization`.
- Adds `/device/code`, `/device/token`, `/device`, `/device/approve`, and `/device/deny`.
- Adds a `deviceCode` schema table with device code, user code, status, expiry, polling interval, client ID, scope, and optional user ID.
- Supports `generate_device_code`, `generate_user_code`, `validate_client`, `on_device_auth_request`, `verification_uri`, `expires_in`, and `interval`.

## Key Differences

- Ruby options use snake_case equivalents of upstream camelCase.
- Successful device-token exchange returns a Better Auth session token as the bearer access token, matching the current Ruby core session primitives.
- Tests use deterministic code generators to avoid brittle randomness.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/device_authorization_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/device_authorization_test.rb`
