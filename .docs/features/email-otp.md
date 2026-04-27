# Feature: Email OTP Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/email-otp/index.ts`, `upstream/packages/better-auth/src/plugins/email-otp/routes.ts`, `upstream/packages/better-auth/src/plugins/email-otp/otp-token.ts`, `upstream/packages/better-auth/src/plugins/email-otp/email-otp.test.ts`

## Summary

Adds one-time-password email flows for email verification, email OTP sign-in/sign-up, and password reset.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.email_otp`.
- Adds `/email-otp/send-verification-otp`, `/email-otp/check-verification-otp`, `/email-otp/verify-email`, `/sign-in/email-otp`, `/email-otp/request-password-reset`, `/forget-password/email-otp`, and `/email-otp/reset-password`.
- Exposes server API helpers `create_verification_otp` and `get_verification_otp`; `get_verification_otp` is also mounted at `/email-otp/get-verification-otp`.
- Stores OTP values in the core `verification` table with identifiers like `email-verification-otp-email@example.com`.
- Supports `otp_length`, `expires_in`, `generate_otp`, `send_verification_otp`, `send_verification_on_sign_up`, `disable_sign_up`, `allowed_attempts`, and `store_otp`.
- Supports plain, hashed, encrypted, custom hasher, and custom encryptor OTP storage.
- Normalizes email casing for OTP sign-in/sign-up flows.
- Prevents user enumeration for disabled sign-up OTP requests by returning success without sending for missing users.
- Verifies the latest issued OTP when multiple OTPs are generated for the same email/type.
- Covers override-default email verification without double-sending and runs configured email verification hooks after OTP verification.
- Applies plugin route rate limits to OTP send, check, verify, sign-in, and password-reset endpoints.

## Key Differences

- Ruby options use snake_case equivalents of upstream camelCase options.
- The plugin defines the Better Auth endpoints and verification/session/password behavior, but delivery is intentionally caller-provided through `send_verification_otp`. Email, SMS, or provider-specific integrations do not live inside the endpoint.
- Hashed OTP storage uses `BetterAuth::Crypto.sha256(..., encoding: :base64url)`, matching upstream's SHA-256/base64url behavior without adding a dependency.
- Encrypted OTP storage uses the core AES-GCM symmetric helper used elsewhere in the Ruby port.
- Browser/client alias helpers are TypeScript client surface and outside the Ruby server scope.

## Testing

```bash
cd packages/better_auth
rbenv exec ruby -Itest test/better_auth/plugins/email_otp_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/email_otp_test.rb`
