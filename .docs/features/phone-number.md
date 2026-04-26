# Feature: Phone Number Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/phone-number/index.ts`, `upstream/packages/better-auth/src/plugins/phone-number/routes.ts`, `upstream/packages/better-auth/src/plugins/phone-number/schema.ts`, `upstream/packages/better-auth/src/plugins/phone-number/phone-number.test.ts`

## Summary

Adds phone-number OTP verification, phone-number sign-in with password, phone-number updates through OTP, and phone-number password reset flows.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.phone_number`.
- Adds `/phone-number/send-otp`, `/phone-number/verify`, `/sign-in/phone-number`, `/phone-number/request-password-reset`, and `/phone-number/reset-password`.
- Extends the user schema with `phoneNumber` and `phoneNumberVerified`.
- Blocks direct `/update-user` changes to `phoneNumber`; phone changes must go through OTP verification.
- Supports `send_otp`, `send_password_reset_otp`, `verify_otp`, `phone_number_validator`, `require_verification`, `callback_on_verification`, `sign_up_on_verification`, `otp_length`, `expires_in`, and `allowed_attempts`.

## Key Differences

- Ruby options and callback payloads use snake_case equivalents of upstream camelCase names.
- The plugin owns Better Auth routing, persistence, session creation, and password reset behavior, but SMS/provider delivery is application-provided through callbacks.
- Custom `verify_otp` can delegate verification to an external SMS provider that stores or validates OTPs outside Better Auth.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/phone_number_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/phone_number_test.rb`
