# Feature: Sessions And Cookies

**Upstream Reference:** `upstream/packages/better-auth/src/cookies/index.ts`, `upstream/packages/better-auth/src/cookies/session-store.ts`, `upstream/packages/better-auth/src/crypto/`, `upstream/packages/better-auth/src/api/routes/session.ts`

## Summary

Phase 4 adds the security-sensitive primitives that later auth routes build on: random IDs, HMAC signatures, symmetric encryption helpers, JWT helpers, upstream-compatible scrypt password storage, Better Auth cookie definitions, signed session-token cookies, session-data cookie cache, chunked cookies, and adapter-backed session lookup/refresh.

## Upstream Implementation

Upstream derives cookie names and attributes from auth options, signs the `session_token`, optionally stores filtered session/user data in `session_data`, chunks oversized cache cookies, and refreshes persisted sessions when `updateAge` is reached. Its cookie cache supports compact HMAC, JWT, and JWE strategies.

## Ruby/Rails Adaptation

Ruby keeps the same cookie names, prefixes, default attributes, max-age behavior, chunking behavior, signed-cookie semantics, cache-version validation, and session refresh rules. Internals are idiomatic Ruby:

- `BetterAuth::Crypto` uses `OpenSSL`, `JWT`, and `SecureRandom`.
- `BetterAuth::Password` uses OpenSSL scrypt by default with upstream parameters, supports optional BCrypt via `password_hasher: :bcrypt`, and still verifies legacy raw BCrypt and `bcrypt_sha256$` hashes when the optional `bcrypt` gem is installed.
- `BetterAuth::Cookies` exposes Ruby `snake_case` option keys while preserving upstream cookie wire names.
- `BetterAuth::Session.find_current` accepts `disable_cookie_cache`, `disable_refresh`, and `sensitive` flags for route-level behavior.

### JWE Strategy

Ruby uses the `jwe` gem to encode `session.cookieCache.strategy = "jwe"` as RFC 7516 compact JWE with `alg = "dir"` and `enc = "A256CBC-HS512"`, matching upstream's public cookie-cache strategy. The encryption key is derived from the Better Auth secret and the `better-auth-session` salt using HKDF-SHA256 with the same info string as upstream: `BetterAuth.js Generated Encryption Key`.

## Implementation

- `packages/better_auth/lib/better_auth/crypto.rb`
- `packages/better_auth/lib/better_auth/password.rb`
- `packages/better_auth/lib/better_auth/cookies.rb`
- `packages/better_auth/lib/better_auth/session_store.rb`
- `packages/better_auth/lib/better_auth/session.rb`
- `packages/better_auth/lib/better_auth/endpoint.rb`
- `packages/better_auth/lib/better_auth/context.rb`

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/crypto_test.rb
rbenv exec ruby -Itest test/better_auth/password_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/cookies_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/session_test.rb
rbenv exec bundle exec rake test
rbenv exec bundle exec standardrb --cache false
```

Key test files:

- `packages/better_auth/test/better_auth/crypto_test.rb`
- `packages/better_auth/test/better_auth/password_test.rb`
- `packages/better_auth/test/better_auth/cookies_test.rb`
- `packages/better_auth/test/better_auth/session_test.rb`

## Notes

Full `/get-session`, sign-in, sign-out, and revocation route coverage remains in Phase 5. Phase 4 focuses on the primitives those routes will call.
