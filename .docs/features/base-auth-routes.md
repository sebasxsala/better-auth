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

## Implemented

- `/ok` returns `{ ok: true }` through Rack and direct API calls.
- `/error` supports sanitized HTML output, invalid-code fallback, configured error URL redirects, and direct API response mode.
- `/sign-up/email` supports JSON and form-urlencoded requests, email normalization, password validation, duplicate-email rejection, user creation, credential account creation, BCrypt password hashing, optional verification email callback, auto sign-in, session cookie creation, `rememberMe: false`, and disabled sign-up handling.
- `/sign-in/email` supports JSON and form-urlencoded requests, email normalization, credential account lookup, BCrypt verification, generic invalid-credential errors, optional email-verification resend on sign-in, session cookie creation, `rememberMe: false`, callback URL response metadata, and session IP/user-agent capture.
- `/sign-out` deletes the current session when a signed session cookie is present, clears session/cache cookies, and returns `{ success: true }`.
- `/get-session`, `/list-sessions`, `/revoke-session`, `/revoke-sessions`, and `/revoke-other-sessions` support the core session read/list/revoke flows against the shared session primitives.

## Ruby Adaptations

- Direct API calls use Ruby snake_case endpoint methods such as `auth.api.sign_up_email`, while route paths and JSON keys remain upstream-compatible.
- Verification email tokens currently use the core HS256 JWT helper introduced in Phase 4. Full `/verify-email` consumption is still part of the remaining Phase 5 route work.
- Additional-field plugin behavior on sign-up remains deferred until the plugin contract and first plugin wave are implemented.
- Route-level session tests use `database: :memory` for revocation parity. DB-less/stateless mode intentionally enables cookie-cache behavior and is covered separately by session/cookie primitive tests.

## Upstream Test Parity

- `error.test.ts`: Ruby covers XSS description sanitization and invalid code fallback.
- `sign-up.test.ts`: Ruby covers core email/password sign-up, empty names, IP/user-agent capture, invalid email/password, duplicate email, disabled sign-up, form-urlencoded requests, route-level CSRF blocking, and `sendOnSignUp` true/false/default behavior. Additional-fields plugin assertions are deferred to Phase 7.
- `sign-in.test.ts`: Ruby covers set-cookie responses, IP/user-agent capture, invalid credentials, email verification required, `sendOnSignIn` true/false behavior, form-urlencoded requests, and route-level CSRF blocking. Social URL checks are deferred with `/sign-in/social`.
- `sign-out.test.ts`: Ruby covers success response, session deletion through the internal adapter, cookie clearing, and delete hooks.
- `session-api.test.ts`: Ruby covers unauthenticated `get-session`, authenticated `get-session`, sign-out clearing, list sessions, revoke one session, revoke all sessions, and revoke other sessions. The broad upstream cookie-cache strategy matrix remains partially covered by `cookies_test.rb` and `session_test.rb`.

## Tests

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/routes/ok_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/error_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/sign_up_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/sign_in_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/sign_out_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/session_routes_test.rb
rbenv exec bundle exec rake test
rbenv exec bundle exec standardrb
```
