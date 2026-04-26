# Base Auth Routes

## Summary

Phase 5 ports Better Auth's base HTTP routes into the framework-agnostic Rack core. The Ruby implementation keeps route paths, JSON keys, session cookie behavior, and error messages aligned with upstream where the supporting primitives already exist.

## Upstream Implementation

- `upstream/packages/better-auth/src/api/routes/ok.ts`
- `upstream/packages/better-auth/src/api/routes/error.ts`
- `upstream/packages/better-auth/src/api/routes/sign-up.ts`
- `upstream/packages/better-auth/src/api/routes/sign-up.test.ts`
- `upstream/packages/better-auth/src/api/routes/sign-in.ts`
- `upstream/packages/better-auth/src/api/routes/sign-in.test.ts`
- `upstream/packages/better-auth/src/api/routes/sign-out.ts`
- `upstream/packages/better-auth/src/api/routes/sign-out.test.ts`
- `upstream/packages/better-auth/src/api/routes/session.ts`
- `upstream/packages/better-auth/src/api/routes/session-api.test.ts`
- `upstream/packages/better-auth/src/api/routes/password.ts`
- `upstream/packages/better-auth/src/api/routes/password.test.ts`
- `upstream/packages/better-auth/src/api/routes/email-verification.ts`
- `upstream/packages/better-auth/src/api/routes/email-verification.test.ts`
- `upstream/packages/better-auth/src/api/routes/update-user.ts`
- `upstream/packages/better-auth/src/api/routes/update-user.test.ts`
- `upstream/packages/better-auth/src/api/routes/account.ts`
- `upstream/packages/better-auth/src/api/routes/account.test.ts`
- `upstream/packages/better-auth/src/api/routes/callback.ts`
- `upstream/packages/better-auth/src/social.test.ts`

## Implemented

- `/ok` returns `{ ok: true }` through Rack and direct API calls.
- `/error` supports sanitized HTML output, invalid-code fallback, configured error URL redirects, and direct API response mode.
- `/sign-up/email` supports JSON and form-urlencoded requests, email normalization, password validation, duplicate-email rejection, user creation, credential account creation, BCrypt password hashing, optional verification email callback, auto sign-in, session cookie creation, `rememberMe: false`, and disabled sign-up handling.
- `/sign-in/email` supports JSON and form-urlencoded requests, email normalization, credential account lookup, BCrypt verification, generic invalid-credential errors, optional email-verification resend on sign-in, session cookie creation, `rememberMe: false`, callback URL response metadata, and session IP/user-agent capture.
- `/sign-in/social` supports provider lookup, direct `idToken` sign-in, OAuth authorization URL creation, signed OAuth state, callback code validation, social user/account persistence, token storage, callback redirects, and session cookies.
- `/sign-out` deletes the current session when a signed session cookie is present, clears session/cache cookies, and returns `{ success: true }`.
- `/get-session`, `/list-sessions`, `/revoke-session`, `/revoke-sessions`, and `/revoke-other-sessions` support the core session read/list/revoke flows against the shared session primitives.
- `/request-password-reset`, `/reset-password/:token`, `/reset-password`, and `/verify-password` support generic reset responses, reset email callbacks, verification records, password update/create, optional session revocation, reset callbacks, and current-password verification.
- `/send-verification-email` and `/verify-email` support no-leak verification email sends, authenticated email mismatch checks, HS256 verification tokens, email verification callbacks, optional auto sign-in, and redirect/error handling.
- `/update-user`, `/change-email`, `/change-password`, `/set-password`, `/delete-user`, and `/delete-user/callback` support authenticated profile updates, guarded email changes, password changes, credential password setup, delete hooks, session cleanup, and token-based delete callbacks.
- `/list-accounts`, `/link-social`, `/unlink-account`, `/get-access-token`, `/refresh-token`, and `/account-info` support account listing, social account linking, unlink guards, provider token lookup, refresh-token callbacks, token persistence, and provider account-info lookup.

## Ruby Adaptations

- Direct API calls use Ruby snake_case endpoint methods such as `auth.api.sign_up_email`, while route paths and JSON keys remain upstream-compatible.
- Verification and OAuth state tokens currently use the core HS256 JWT helper introduced in Phase 4.
- Additional-field plugin behavior on sign-up/update remains deferred until the first plugin wave is implemented.
- Social provider support is duck-typed for Ruby hashes/objects with callables such as `verify_id_token`, `get_user_info`, `create_authorization_url`, `validate_authorization_code`, and `refresh_access_token`.
- Route-level session tests use `database: :memory` for revocation parity. DB-less/stateless mode intentionally enables cookie-cache behavior and is covered separately by session/cookie primitive tests.

## Upstream Test Parity

- `error.test.ts`: Ruby covers XSS description sanitization and invalid code fallback.
- `sign-up.test.ts`: Ruby covers core email/password sign-up, empty names, IP/user-agent capture, invalid email/password, duplicate email, disabled sign-up, form-urlencoded requests, route-level CSRF blocking, and `sendOnSignUp` true/false/default behavior. Additional-fields plugin assertions are deferred to Phase 7.
- `sign-in.test.ts` and `social.test.ts`: Ruby covers set-cookie responses, IP/user-agent capture, invalid credentials, email verification required, `sendOnSignIn` true/false behavior, form-urlencoded requests, route-level CSRF blocking, direct social ID-token sign-in, OAuth authorization URL generation, callback session creation, token storage, and social linking.
- `sign-out.test.ts`: Ruby covers success response, session deletion through the internal adapter, cookie clearing, and delete hooks.
- `session-api.test.ts`: Ruby covers unauthenticated `get-session`, authenticated `get-session`, sign-out clearing, list sessions, revoke one session, revoke all sessions, and revoke other sessions. The broad upstream cookie-cache strategy matrix remains partially covered by `cookies_test.rb` and `session_test.rb`.
- `password.test.ts`: Ruby covers generic reset responses, callback redirects, reset token records, password update, reset hooks, session revocation, and password verification.
- `email-verification.test.ts`: Ruby covers no-leak verification sends, authenticated mismatch rejection, verification callbacks, emailVerified updates, and auto sign-in cookies.
- `update-user.test.ts`: Ruby covers profile updates, email-update rejection, password changes with session revocation, password setup, email changes, and user deletion hooks/session cleanup.
- `account.test.ts`: Ruby covers account listing, unlink guards, token lookup/refresh, provider token persistence, account info, and social account linking.

## Tests

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/routes/ok_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/error_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/sign_up_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/sign_in_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/social_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/sign_out_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/session_routes_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/password_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/email_verification_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/user_routes_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/account_test.rb
rbenv exec bundle exec rake test
rbenv exec bundle exec standardrb
```
