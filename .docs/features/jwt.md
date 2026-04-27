# Feature: JWT/JWKS Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/jwt/index.ts`, `upstream/packages/better-auth/src/plugins/jwt/jwt.test.ts`, `upstream/packages/better-auth/src/plugins/jwt/rotation.test.ts`

## Summary

Issues JWTs for authenticated sessions, publishes JWKS, and exposes server-side sign/verify API helpers.

Status: Complete for Ruby server parity.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.jwt`.
- Implements `/token`, configurable `/jwks`, API-only `sign_jwt`, API-only `verify_jwt`, and `set-auth-jwt` get-session header.
- Uses upstream-compatible EdDSA (`Ed25519`) signing by default and supports `RS256`, `PS256`, `ES256`, and `ES512` through Ruby OpenSSL.
- Stores public/private key material in the plugin `jwks` schema and publishes RSA, EC, and OKP public JWKS fields.
- Supports remote JWKS URL validation, disables local JWKS endpoint when remote mode is configured, and verifies tokens against injected or fetched remote JWKS.
- Supports key rotation when the latest key is expired and keeps expired public keys visible during the configured JWKS grace period.
- Selects verification keys by `kid`, verifies current and previous keys, honors token expiry, and keeps API-only `sign_jwt`/`verify_jwt` helpers server-side.

## Notes

Symmetric client-secret algorithms such as `HS256` are intentionally outside the JWKS plugin surface because upstream JWT/JWKS behavior is based on asymmetric public key publication. Custom remote signing is still supported through the `jwt.sign` callable when `jwks.remote_url` is configured.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/jwt_test.rb
```
