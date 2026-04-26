# Base Auth Routes

## Summary

Phase 5 ports Better Auth's base HTTP routes into the framework-agnostic Rack core. The Ruby implementation keeps route paths, JSON keys, session cookie behavior, and error messages aligned with upstream where the supporting primitives already exist.

## Upstream Implementation

- `upstream/packages/better-auth/src/api/routes/ok.ts`
- `upstream/packages/better-auth/src/api/routes/error.ts`
- `upstream/packages/better-auth/src/api/routes/sign-up.ts`
- `upstream/packages/better-auth/src/api/routes/sign-up.test.ts`

## Implemented

- `/ok` returns `{ ok: true }` through Rack and direct API calls.
- `/error` supports sanitized HTML output, invalid-code fallback, configured error URL redirects, and direct API response mode.
- `/sign-up/email` supports JSON and form-urlencoded requests, email normalization, password validation, duplicate-email rejection, user creation, credential account creation, BCrypt password hashing, optional verification email callback, auto sign-in, session cookie creation, `rememberMe: false`, and disabled sign-up handling.
- `/sign-in/email` supports JSON and form-urlencoded requests, email normalization, credential account lookup, BCrypt verification, generic invalid-credential errors, optional email-verification resend on sign-in, session cookie creation, `rememberMe: false`, callback URL response metadata, and session IP/user-agent capture.

## Ruby Adaptations

- Direct API calls use Ruby snake_case endpoint methods such as `auth.api.sign_up_email`, while route paths and JSON keys remain upstream-compatible.
- Verification email tokens currently use the core HS256 JWT helper introduced in Phase 4. Full `/verify-email` consumption is still part of the remaining Phase 5 route work.
- Additional-field plugin behavior on sign-up remains deferred until the plugin contract and first plugin wave are implemented.

## Tests

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/routes/ok_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/error_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/sign_up_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/sign_in_test.rb
rbenv exec bundle exec rake test
rbenv exec bundle exec standardrb
```
