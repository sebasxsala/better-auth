# Email OTP Plugin Upstream Parity Child Plan

**Parent:** `.docs/plans/2026-04-30-core-plugins-upstream-parity.md`

**Upstream source:** `upstream/packages/better-auth/src/plugins/email-otp/email-otp.test.ts`

**Ruby target:** `packages/better_auth/test/better_auth/plugins/email_otp_test.rb`

## Status

- [x] Extracted upstream server-applicable test titles from Better Auth v1.6.9.
- [x] Mapped upstream titles to Ruby Minitest coverage.
- [x] Documented Ruby exclusions.
- [x] Fixed discovered Ruby parity gaps for email OTP sign-up additional-field filtering and disabled sign-up error behavior.
- [x] Ran focused Ruby test file.
- [x] Ran focused StandardRB lint on touched email OTP files.
- [x] Ran full core package test suite outside sandbox after local TCP/database checks were blocked in sandbox.

## Coverage Matrix

| Upstream title group | Ruby coverage | Status | Notes |
| --- | --- | --- | --- |
| Verify email with OTP, sign in with OTP, sign up with OTP, profile/image/additional fields, input-false/default handling, uppercase/varying-case email normalization | `test_sends_and_verifies_email_otp_for_existing_user`, `test_sign_in_with_email_otp_creates_session_and_can_sign_up_new_users`, `test_sign_in_with_email_otp_sign_up_preserves_profile_and_additional_fields`, `test_sign_in_with_email_otp_sign_up_ignores_input_false_fields_and_uses_default`, `test_sign_in_with_email_otp_normalizes_email_case` | Covered by Ruby test | Ruby tests assert real user/session records, response payloads, and upstream-compatible input-false filtering for email OTP sign-up. |
| Send verification OTP on sign-up and override default email verification | `test_send_verification_on_sign_up_uses_configured_delivery_callback`, `test_override_default_email_verification_sends_once_and_calls_after_hook` | Covered by existing Ruby test | Includes "send once" and after-hook behavior. |
| Password reset through email OTP, deprecated compatibility behavior, callback, credential-account creation, session revocation | `test_password_reset_with_email_otp_updates_password_and_revokes_sessions` | Covered by existing Ruby test | Ruby keeps the behavior under the plugin reset endpoint surface. |
| Invalid email, rejected change-email type, expired OTP, elapsed-time tolerance | `test_expired_email_otp_is_rejected_and_consumed`, `test_send_verification_otp_rejects_change_email_type_with_upstream_message` | Covered by existing Ruby test | Invalid email validation is covered by route validation in the same suite. |
| Server OTP helpers: create/get, custom length, rate-limit storage, secure storage modes | `test_server_otp_helpers_support_custom_length_and_secure_storage_modes`, `test_server_otp_helpers_support_custom_encryptor_and_hasher_storage`, `test_email_otp_routes_use_plugin_rate_limits` | Covered by existing Ruby test | Covers plain, hashed, encrypted, custom encryptor, and custom hasher modes. |
| Change email request and change flows, current-email verification, session/invalid-session failures, before/after verification hooks | `test_email_otp_change_email_flow` | Covered by existing Ruby test | Condensed Ruby integration test covers the server-applicable path and failure edges. |
| Enumeration prevention when sign-up is disabled or non-existent user requests email verification | `test_send_verification_otp_prevents_enumeration_when_sign_up_is_disabled`, `test_sign_in_with_email_otp_returns_invalid_otp_when_sign_up_is_disabled` | Covered by Ruby test | Asserts no delivery for unknown users when disabled and returns upstream-compatible `Invalid OTP` for blocked sign-in. |
| Last OTP wins, attempt limits, reset-password attempt limits, fresh OTP after exhausted attempts | `test_email_otp_verifies_last_issued_otp`, `test_check_otp_tracks_attempts_and_rejects_too_many_failures`, `test_consuming_invalid_otp_recreates_verification_with_incremented_attempts` | Covered by existing Ruby test | Exercises real verification rows. |
| Resend strategy reuse/new OTP behavior, hashed/custom-hash non-reuse | `test_email_otp_reuses_recoverable_otp_when_configured` | Covered by existing Ruby test | Ruby verifies reuse only where the OTP can be recovered. |
| Race-condition cleanup after successful sign-in/email verification/password reset | `test_sends_and_verifies_email_otp_for_existing_user`, `test_sign_in_with_email_otp_creates_session_and_can_sign_up_new_users`, `test_password_reset_with_email_otp_updates_password_and_revokes_sessions` | Covered by existing Ruby test | Verified by consumed/deleted verification records. |
| Type inference and client package behavior | N/A | Ruby exclusion documented | No Ruby runtime behavior in `better_auth` core. |

## Verification

- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/email_otp_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec standardrb lib/better_auth/plugins/email_otp.rb test/better_auth/plugins/email_otp_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec rake test`
