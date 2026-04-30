# Core Base Routes Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port Ruby-applicable upstream base route tests into `packages/better_auth`.

**Architecture:** Keep each route family in its existing route file and add focused Minitest coverage to the matching route test file. Prefer integration-style direct API and Rack tests using the memory adapter.

**Tech Stack:** Ruby 3.2+, Minitest, Rack, BetterAuth memory adapter.

---

## Audit Summary

Upstream files:

- `api/routes/account.test.ts` — 23 titles
- `api/routes/password.test.ts` — 23 titles
- `api/routes/session-api.test.ts` — 56 titles
- `api/routes/sign-up.test.ts` — 27 titles
- `api/routes/sign-in.test.ts` — 13 titles
- `api/routes/email-verification.test.ts` — 17 titles
- `api/routes/update-user.test.ts` — 21 titles
- `api/routes/sign-out.test.ts` — 1 title
- `api/routes/error.test.ts` — 2 titles

Existing Ruby targets:

- `routes/account_test.rb` — 5 tests
- `routes/password_test.rb` — 5 tests
- `routes/session_routes_test.rb` — 16 tests
- `routes/sign_up_test.rb` — 15 tests
- `routes/sign_in_test.rb` — 8 tests
- `routes/email_verification_test.rb` — 7 tests
- `routes/user_routes_test.rb` — 11 tests
- `routes/sign_out_test.rb` — 1 test
- `routes/error_test.rb` — 4 tests

Differences found:

- Ruby route tests cover the main flows but often collapse multiple upstream titles into one broader test.
- Session API has the largest gap: cookie refresh, no-cookie/null cases, fresh-session checks, disable refresh, cache refresh, list/revoke variants, secondary storage, and cookie options need title-aligned coverage.
- Sign-up and sign-in are partially covered, but upstream has more rollback, additional field, verification, origin, disabled signup, and email normalization cases.
- Account route coverage is light relative to upstream: link/unlink edge cases, token encryption/decryption, provider account ID lookup, refresh-token behavior, and account info cases need expansion.
- Password/update-user/email-verification coverage needs more callback, token, trusted redirect, password verification, email-change, delete-user, and hook behavior coverage.

## Tasks

### Task 1: Session Routes

**Files:**
- Modify: `packages/better_auth/test/better_auth/routes/session_routes_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/session.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/session.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/cookies.rb`

- [x] Translate upstream get-session cases: unauthenticated null, authenticated payload, fresh-session requirement, stale-session rejection, expiration, refresh update age, update age zero, `disableRefresh`, and sensitive route cache bypass.
- [x] Translate cookie behavior cases: session cookie, cache cookie, remember-me false, `disableCookieCache`, tampered cache fallback, refresh cache, and response cookie attributes.
- [x] Translate list/revoke cases: list current user sessions, revoke one, revoke all, revoke others, secondary storage preservation/deletion variants, and missing-session behavior.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/routes/session_routes_test.rb`.

### Task 2: Sign-Up And Sign-In Routes

**Files:**
- Modify: `packages/better_auth/test/better_auth/routes/sign_up_test.rb`
- Modify: `packages/better_auth/test/better_auth/routes/sign_in_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/sign_up.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/sign_in.rb`

- [x] Translate sign-up cases for custom account fields, empty name, headers/IP/user-agent, rollback on session failure, `input: false` field protection, duplicate email, email normalization, verification-required responses, disabled signup, and form JSON media behavior.
- [x] Translate sign-in cases for cookie header, IP/user-agent capture, verification email send/no-send, untrusted origin rejection, invalid credentials, email verification requirement, and form-encoded Rack requests.
- [x] Run sign-up/sign-in route tests.

### Task 3: Account And Social Account Routes

**Files:**
- Modify: `packages/better_auth/test/better_auth/routes/account_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/account.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/social.rb`

- [x] Translate account-list cases, including scopes array and provider account ID lookup.
- [x] Translate link-account cases for first account, verified email updating, unverified provider no-op, case-insensitive email matching, account already linked, and trusted provider behavior.
- [x] Translate unlink cases for last-account rejection, non-owned account protection, and provider/account ID matching.
- [x] Translate get-access-token and refresh-token cases for encrypted/plain token migration, provider refresh callbacks, same-provider account selection, and account info calls.
- [x] Run account and social route tests.

### Task 4: Password, Email Verification, And User Update Routes

**Files:**
- Modify: `packages/better_auth/test/better_auth/routes/password_test.rb`
- Modify: `packages/better_auth/test/better_auth/routes/email_verification_test.rb`
- Modify: `packages/better_auth/test/better_auth/routes/user_routes_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/password.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/email_verification.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/user.rb`

- [x] Translate password reset request/callback/reset cases: enabled callback, generic missing-user response, trusted redirect rejection, invalid token, password validation, custom callbacks, and session revocation.
- [x] Translate email verification cases: send when enabled, required verification, verify email, callback redirect, sign-in after verification, token expiration, callback URL validation, and change-email verification flow.
- [x] Translate update-user cases: name/image updates, secure email-change default, confirmation flow, password update, set password, delete user, fresh session requirement, verification token deletion, and secondary storage propagation.
- [x] Run password/email/user route tests.

### Task 5: Error And Sign-Out Routes

**Files:**
- Modify: `packages/better_auth/test/better_auth/routes/error_test.rb`
- Modify: `packages/better_auth/test/better_auth/routes/sign_out_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/error.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/routes/sign_out.rb`

- [x] Confirm upstream error sanitization tests remain covered by Ruby HTML/direct API variants.
- [x] Confirm sign-out success, session deletion, cookie clearing, hook execution, and no-session success behavior.
- [x] Add missing assertions only where upstream behavior is not already explicit.
- [x] Run error/sign-out tests.

### Task 6: Final Verification

**Files:**
- Modify: `.docs/plans/2026-04-30-core-base-routes-upstream-parity.md`
- Modify: `.docs/plans/2026-04-29-core-upstream-test-parity.md`

- [x] Mark every base-route upstream title as `Ported`, `Covered by existing Ruby test`, or `Ruby exclusion documented`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec rake test`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec standardrb`.

## Upstream Title Status Matrix

Status legend:
- `Ported`: Added or tightened Ruby coverage in this plan.
- `Covered by existing Ruby test`: Existing Ruby route/plugin/helper tests already covered the upstream behavior, sometimes with broader integration tests.
- `Ruby exclusion documented`: The upstream title is TypeScript/client/runtime-specific or targets an option not exposed by the Ruby core API.

### `account.test.ts`

| Upstream title | Status |
| --- | --- |
| should list all accounts | Covered by existing Ruby test |
| should link first account | Covered by existing Ruby test |
| should encrypt access token and refresh token | Covered by existing Ruby test |
| should get access token using accountId from listAccounts | Covered by existing Ruby test |
| should get account info using provider accountId (not internal id) | Ported |
| should pass custom scopes to authorization URL | Covered by existing Ruby test |
| should link second account from the same provider | Covered by existing Ruby test |
| should link third account with idToken | Covered by existing Ruby test |
| should unlink account | Covered by existing Ruby test |
| should fail to unlink the last account of a provider | Covered by existing Ruby test |
| should unlink account with specific accountId | Covered by existing Ruby test |
| should unlink all accounts with specific providerId | Covered by existing Ruby test |
| should store account data cookie after oauth flow and retrieve it through getAccessToken | Covered by existing Ruby test |
| should use account cookie when accountId is omitted in getAccessToken | Covered by existing Ruby test |
| should match account cookie by accountId in getAccessToken when accountId is provided | Covered by existing Ruby test |
| should persist refreshed idToken in database during getAccessToken auto-refresh | Covered by existing Ruby test |
| should persist refreshed idToken in account cookie during getAccessToken auto-refresh in stateless mode | Covered by existing Ruby test |
| should NOT chunk account data cookies when exceeding 4KB | Covered by existing Ruby test |
| should chunk account data cookies when exceeding 4KB | Covered by existing Ruby test |
| should encrypt account cookie payload | Covered by existing Ruby test |
| should set account cookie on re-login after sign-out when updateAccountOnSignIn is false | Covered by existing Ruby test |
| should refresh account_data cookie when session is refreshed | Covered by existing Ruby test |
| should refresh account_data cookie in stateless mode | Covered by existing Ruby test |

### `password.test.ts`

| Upstream title | Status |
| --- | --- |
| should send a reset password email when enabled | Covered by existing Ruby test |
| should reject untrusted redirectTo | Ported |
| should fail on invalid password | Ported |
| should verify the token | Covered by existing Ruby test |
| should update account's updatedAt when resetting password | Covered by existing Ruby test |
| should sign-in with the new password | Covered by existing Ruby test |
| shouldn't allow the token to be used twice | Ported |
| should expire | Covered by existing Ruby test |
| should allow callbackURL to have multiple query params | Covered by existing Ruby test |
| should not reveal user existence on success | Covered by existing Ruby test |
| should not reveal user existence on failure | Covered by existing Ruby test |
| should not reveal failure of email sending | Covered by existing Ruby test |
| should revoke other sessions when revokeSessionsOnPasswordReset is enabled | Covered by existing Ruby test |
| should not revoke other sessions by default | Ported |
| should verify password with correct password | Covered by existing Ruby test |
| should fail to verify password with incorrect password | Covered by existing Ruby test |
| should require a session to verify password | Ported |

### `session-api.test.ts`

| Upstream title | Status |
| --- | --- |
| should set cookies correctly on sign in | Ported |
| should return null when not authenticated | Covered by existing Ruby test |
| should require a fresh session based on session creation time | Covered by existing Ruby test |
| should update session when update age is reached | Ported |
| should update the session every time when set to 0 | Covered by existing Ruby test |
| should handle 'don't remember me' option | Covered by existing Ruby test |
| should set cookies correctly on sign in after changing config | Ported |
| should clear session on sign out | Covered by existing Ruby test |
| should list sessions | Covered by existing Ruby test |
| should revoke session | Covered by existing Ruby test |
| should return session headers | Covered by existing Ruby test |
| should store session in secondary storage | Covered by existing Ruby test |
| revoke session and list sessions | Covered by existing Ruby test |
| should cache cookies | Covered by existing Ruby test |
| should disable cookie cache | Covered by existing Ruby test |
| should reset cache when expires | Covered by existing Ruby test |
| should cache cookies with JWT strategy | Covered by existing Ruby test |
| should not allow tampering with the cookie | Covered by existing Ruby test |
| should have max age expiry | Covered by existing Ruby test |
| should handle multiple concurrent requests with JWT cache | Covered by existing Ruby test |
| should cache cookies with JWE strategy | Covered by existing Ruby test |
| should disable cookie cache with JWE strategy | Covered by existing Ruby test |
| should reset JWE cache when expires | Covered by existing Ruby test |
| should handle multiple concurrent requests with JWE cache | Covered by existing Ruby test |
| should use cached data when refreshCache threshold has not been reached | Covered by existing Ruby test |
| should not perform stateless refresh when a database is configured | Covered by existing Ruby test |
| should not refresh cache when refreshCache is disabled (false) | Covered by existing Ruby test |
| should work without database (session stored in cookie only) | Covered by existing Ruby test |
| should work without database when refreshCache threshold is reached | Ported |
| should extend session_token cookie expiry when refreshCache threshold is reached | Ported |
| should invalidate cookie cache when version changes (string version) | Ported |
| should work with function-based version | Covered by existing Ruby test |
| should work with async function-based version | Ruby exclusion documented |
| should work with compact strategy | Covered by existing Ruby test |
| should work with jwt strategy | Covered by existing Ruby test |
| should default to version '1' when not specified | Covered by existing Ruby test |
| should include additionalFields when retrieving from cookie cache | Covered by existing Ruby test |
| should return needsRefresh flag on GET when enabled | Ruby exclusion documented |
| should return needsRefresh: false when session is fresh | Ruby exclusion documented |
| should not update session on GET when deferSessionRefresh is enabled | Ruby exclusion documented |
| should update session on POST when deferSessionRefresh is enabled | Ruby exclusion documented |
| should reject POST when deferSessionRefresh is not enabled | Ruby exclusion documented |
| should not delete expired session on GET when deferSessionRefresh is enabled | Ruby exclusion documented |
| should delete expired session on POST when deferSessionRefresh is enabled | Ruby exclusion documented |
| should still update session on GET when deferSessionRefresh is not enabled (default behavior) | Ported |
| should respect disableSessionRefresh config when deferSessionRefresh is enabled | Ruby exclusion documented |
| should have consistent date types between cookie cache and refresh paths | Covered by existing Ruby test |
| should update a custom additional field on a session | Covered by existing Ruby test |
| should ignore core session fields | Covered by existing Ruby test |
| should ignore core field userId | Covered by existing Ruby test |
| should reject input: false fields | Covered by existing Ruby test |
| should return error when no fields to update | Covered by existing Ruby test |
| should update session cookie after mutation | Covered by existing Ruby test |

### `sign-up.test.ts`

| Upstream title | Status |
| --- | --- |
| should work with custom fields on account table | Covered by existing Ruby test |
| should succeed when passing empty name | Covered by existing Ruby test |
| should get the ipAddress and userAgent from headers | Covered by existing Ruby test |
| should rollback when session creation fails | Ported |
| should not allow user to set the field that is set to input: false | Ported |
| should return additionalFields in signUpEmail response | Ported |
| should throw status code 400 when passing invalid body | Covered by existing Ruby test |
| should return success for existing email when email verification is required | Covered by existing Ruby test |
| should call onExistingUserSignUp when requireEmailVerification is true | Covered by existing Ruby test |
| should call onExistingUserSignUp when autoSignIn is false and requireEmailVerification is true | Covered by existing Ruby test |
| should not call onExistingUserSignUp when autoSignIn is false without requireEmailVerification | Ported |
| should not call onExistingUserSignUp when enumeration protection is inactive | Covered by existing Ruby test |
| should not call onExistingUserSignUp for new user sign-ups | Covered by existing Ruby test |
| should throw for existing email when autoSignIn is disabled without requireEmailVerification | Ported |
| should return token: null for new sign-up when autoSignIn is disabled | Ported |
| should block cross-site navigation sign-up attempts (no cookies) | Covered by existing Ruby test |
| should allow same-origin navigation sign-up attempts | Covered by existing Ruby test |
| should allow fetch/XHR sign-up requests (cors mode) | Covered by existing Ruby test |
| should use origin validation when cookies exist | Covered by existing Ruby test |
| should accept form-urlencoded content type | Covered by existing Ruby test |
| should block cross-site form submissions | Covered by existing Ruby test |
| should allow same-site form submissions from trusted origins | Covered by existing Ruby test |
| should not send verification email when sendOnSignUp is false, even with requireEmailVerification | Covered by existing Ruby test |
| should send verification email when sendOnSignUp is true | Covered by existing Ruby test |
| should send verification email when sendOnSignUp is not set but requireEmailVerification is true (default) | Covered by existing Ruby test |
| should return same keys in same order for real and synthetic user | Covered by existing Ruby test |
| should return indistinguishable response with admin plugin fields | Covered by existing Ruby test |

### `sign-in.test.ts`

| Upstream title | Status |
| --- | --- |
| should return a response with a set-cookie header | Covered by existing Ruby test |
| should read the ip address and user agent from the headers | Covered by existing Ruby test |
| verification email will be sent if sendOnSignIn is enabled | Covered by existing Ruby test |
| verification email will not be sent if sendOnSignIn is disabled | Covered by existing Ruby test |
| should reject untrusted origins | Ported |
| should block cross-site navigation login attempts (no cookies) | Covered by existing Ruby test |
| should allow same-origin navigation login attempts | Covered by existing Ruby test |
| should allow fetch/XHR requests (cors mode) | Covered by existing Ruby test |
| should use origin validation when cookies exist | Covered by existing Ruby test |
| should return additionalFields in signInEmail response | Ported |
| should accept form-urlencoded content type | Covered by existing Ruby test |
| should block cross-site form submissions | Covered by existing Ruby test |
| should allow same-site form submissions from trusted origins | Covered by existing Ruby test |

### `email-verification.test.ts`

| Upstream title | Status |
| --- | --- |
| should send a verification email when enabled | Covered by existing Ruby test |
| should send a verification email if verification is required and user is not verified | Covered by existing Ruby test |
| should verify email | Covered by existing Ruby test |
| should redirect to callback | Ported |
| should sign after verification | Covered by existing Ruby test |
| should use custom expiresIn | Ported |
| should call afterEmailVerification callback when email is verified | Covered by existing Ruby test |
| should call beforeEmailVerification callback when email is verified | Covered by existing Ruby test |
| should preserve encoded characters in callback URL | Ported |
| should properly encode callbackURL with query parameters when sending verification email | Covered by existing Ruby test |
| should not send verification email when a third party requests for an already verified user | Covered by existing Ruby test |
| should change email | Covered by existing Ruby test |
| should set emailVerified on all sessions | Covered by existing Ruby test |
| should call hooks when verifying email change (change-email-verification) | Covered by existing Ruby test |

### `update-user.test.ts`

| Upstream title | Status |
| --- | --- |
| should update the user's name | Covered by existing Ruby test |
| should unset image | Covered by existing Ruby test |
| should not update user email immediately (default secure flow) | Covered by existing Ruby test |
| should verify email change (flow with confirmation) | Covered by existing Ruby test |
| should update the user's password | Covered by existing Ruby test |
| should update account's updatedAt when changing password | Covered by existing Ruby test |
| should not update password if current password is wrong | Covered by existing Ruby test |
| should revoke other sessions | Covered by existing Ruby test |
| shouldn't pass defaults | Covered by existing Ruby test |
| should propagate updates across sessions when secondaryStorage is enabled | Covered by existing Ruby test |
| should not write to secondary storage multiple times for the same session token during updateUser | Covered by existing Ruby test |
| should not allow updating user with additional fields that are input: false | Ported |
| should not delete user if deleteUser is disabled | Ported |
| should delete the user with a fresh session | Covered by existing Ruby test |
| should require password when session is no longer fresh | Covered by existing Ruby test |
| should delete every session from deleted user | Covered by existing Ruby test |
| should delete with verification flow and password | Ported |
| should ignore cookie cache for sensitive operations like changePassword | Covered by existing Ruby test |
| should return 200 when target email already exists | Ported |
| should not change the user's email | Ported |
| should return the same error for existing and non-existing emails | Ported |

### `sign-out.test.ts`

| Upstream title | Status |
| --- | --- |
| should sign out | Ported |

### `error.test.ts`

| Upstream title | Status |
| --- | --- |
| should sanitize error description to prevent XSS | Covered by existing Ruby test |
| should sanitize code parameter | Covered by existing Ruby test |
