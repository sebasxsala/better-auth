# Feature: JWT/JWKS Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/jwt/index.ts`, `upstream/packages/better-auth/src/plugins/jwt/jwt.test.ts`, `upstream/packages/better-auth/src/plugins/jwt/rotation.test.ts`

## Summary

Issues JWTs for authenticated sessions, publishes JWKS, and exposes server-side sign/verify API helpers.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.jwt`.
- Implements `/token`, configurable `/jwks`, API-only `sign_jwt`, API-only `verify_jwt`, and `set-auth-jwt` get-session header.
- Uses RSA `RS256` keys generated via Ruby OpenSSL and stored in the plugin `jwks` schema.
- Supports remote JWKS URL validation and disables local JWKS endpoint when remote mode is configured.

## Notes

Upstream supports a larger JOSE algorithm matrix and rotation coverage. Ruby currently implements the first compatible RS256 path; broader algorithm/rotation parity remains future hardening.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/jwt_test.rb
```
