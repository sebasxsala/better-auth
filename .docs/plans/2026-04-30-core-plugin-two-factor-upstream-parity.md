# Two Factor Plugin Upstream Parity Child Plan

**Parent:** `.docs/plans/2026-04-30-core-plugins-upstream-parity.md`

**Upstream source:** `upstream/packages/better-auth/src/plugins/two-factor/two-factor.test.ts`

**Ruby target:** `packages/better_auth/test/better_auth/plugins/two_factor_test.rb`

## Status

- [x] Extracted upstream server-applicable test titles from Better Auth v1.6.9.
- [x] Mapped upstream titles to Ruby Minitest coverage.
- [x] Documented Ruby exclusions.
- [x] Ran focused Ruby test file.
- [x] Added missing Ruby parity for TOTP `verified` enrollment state, migration-safe null handling, and re-enrollment preservation.
- [x] Added missing Ruby parity for sign-in `twoFactorMethods` response selection.
- [x] Added missing Ruby parity for passwordless two-factor management when no credential account exists.
- [x] Added missing Ruby parity for custom two-factor physical table name schema mapping.

## Coverage Matrix

| Upstream title group | Ruby coverage | Status | Notes |
| --- | --- | --- | --- |
| Enable TOTP, URI/backup codes before activation, custom/default issuer, require second factor, invalid code errors | `test_enable_then_verify_totp_requires_second_factor_on_next_sign_in` | Covered by existing Ruby test | Ruby validates enrollment and subsequent sign-in challenge. |
| Two-factor API enable/get URI/request/send OTP/verify OTP/disable | `test_enable_then_verify_totp_requires_second_factor_on_next_sign_in`, `test_disable_two_factor_revokes_trusted_device` | Covered by existing Ruby test | OTP delivery is injected and asserted through real verification. |
| Backup codes parse/regenerate/update/use, storage preservation after use | `test_backup_code_use_consumes_code_and_trusting_device_skips_next_challenge` | Covered by existing Ruby test | Ruby covers consumption and trust-device effect. |
| Trust device persistence, expiry, revoke on disable, max-age defaults/customization | `test_backup_code_use_consumes_code_and_trusting_device_skips_next_challenge`, `test_disable_two_factor_revokes_trusted_device` | Covered by existing Ruby test | Cookie max-age is covered separately. |
| Two-factor cookie max age and trust-device cookie max age | `test_two_factor_cookie_max_age_options_are_applied` | Covered by existing Ruby test | Includes configured cookie options. |
| OTP storage modes: plain, hashed, encrypted, custom hash; attempt limits | `test_otp_verification_supports_hashed_storage_and_attempt_limits`, `test_otp_verification_supports_encrypted_and_custom_hash_storage` | Covered by existing Ruby test | Uses real verification rows. |
| Pre-migration rows, re-enrollment verified state, OTP fallback for unverified TOTP | `test_enable_marks_totp_unverified_then_verify_marks_verified`, `test_nil_verified_totp_row_completes_enrollment`, `test_verified_state_is_preserved_when_re_enrolling_totp`, `test_unverified_totp_is_rejected_during_sign_in_but_otp_fallback_works` | Covered by new Ruby tests | Ruby now stores `verified`, treats nil/absent rows as migration-safe, rejects explicitly unverified TOTP at sign-in, and preserves verified state on re-enrollment. |
| Passwordless users vs credential password requirement and non-leaking password errors | `test_passwordless_users_can_manage_two_factor_when_allowed`, `test_allow_passwordless_still_requires_password_for_credential_users` | Covered by new Ruby tests | Ruby supports `allow_passwordless` when credential account is absent and keeps password required when a credential account exists. |
| `twoFactorMethods` sign-in response combinations and 2FA enforcement scope | `test_enable_then_verify_totp_requires_second_factor_on_next_sign_in`, `test_sign_in_response_includes_available_two_factor_methods`, `test_totp_is_excluded_from_sign_in_methods_when_disabled`, `test_unverified_totp_is_rejected_during_sign_in_but_otp_fallback_works`, `test_second_factor_verification_preserves_dont_remember_me_session` | Covered by new Ruby tests | Covers response-driven challenge flow, TOTP/OTP method selection, disabled TOTP, unverified TOTP exclusion, and session preservation. |
| Custom table name for two-factor data | `test_custom_two_factor_table_option_maps_schema_model_name` | Covered by new Ruby test | Ruby adapts upstream `twoFactorTable` as `two_factor_table`, mapping the physical schema table name while retaining logical model key `twoFactor`. |
| Type inference and client-only exposure assertions | N/A | Ruby exclusion documented | No Ruby runtime behavior in `better_auth` core. |

## Verification

- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/two_factor_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/schema_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/schema/sql_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec standardrb lib/better_auth/plugins/two_factor.rb test/better_auth/plugins/two_factor_test.rb`
