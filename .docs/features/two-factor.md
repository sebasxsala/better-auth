# Feature: Two-Factor Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/two-factor/index.ts`, `upstream/packages/better-auth/src/plugins/two-factor/totp/index.ts`, `upstream/packages/better-auth/src/plugins/two-factor/otp/index.ts`, `upstream/packages/better-auth/src/plugins/two-factor/backup-codes/index.ts`, `upstream/packages/better-auth/src/plugins/two-factor/verify-two-factor.ts`, `upstream/packages/better-auth/src/plugins/two-factor/two-factor.test.ts`

## Summary

Adds TOTP, OTP, backup-code, trusted-device, enable/disable, and post-login two-factor flows.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.two_factor`.
- Adds `/two-factor/enable`, `/two-factor/disable`, `/two-factor/get-totp-uri`, `/two-factor/verify-totp`, `/two-factor/send-otp`, `/two-factor/verify-otp`, `/two-factor/verify-backup-code`, and `/two-factor/generate-backup-codes`.
- Adds server API helper `view_backup_codes`.
- Adds `twoFactorEnabled` to `user` and a `twoFactor` table with encrypted TOTP secret, backup codes, and `userId`.
- Uses stdlib `OpenSSL::HMAC` for RFC 6238 TOTP, core AES-GCM symmetric encryption for secrets/codes, and SHA-256/base64url for hashed OTP storage.
- Uses signed `better-auth.two_factor` and `better-auth.trust_device` cookies with server-side verification-table records.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/two_factor_test.rb
```
