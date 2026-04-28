# Feature: Passkey Plugin

Status: Extracted to `better_auth-passkey`; complete for Ruby server parity, including the upstream v1.6 passkey-first registration additions.

**Upstream Reference:** `upstream/packages/passkey/src/index.ts`, `upstream/packages/passkey/src/routes.ts`, `upstream/packages/passkey/src/schema.ts`, `upstream/packages/passkey/src/passkey.test.ts`. The local submodule is pinned to upstream v1.6.9.

## Summary

Adds passkey/WebAuthn registration, authentication, listing, renaming, and deletion through the upstream passkey route contract.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.passkey` after installing `better_auth-passkey` and requiring `better_auth/passkey`.
- Uses the maintained `webauthn` gem (`cedarcode/webauthn-ruby`) from the external package for WebAuthn option generation, attestation verification, assertion verification, signature checks, origin checks, RP ID checks, and sign-count checks.
- Adds `/passkey/generate-register-options`, `/passkey/verify-registration`, `/passkey/generate-authenticate-options`, `/passkey/verify-authentication`, `/passkey/list-user-passkeys`, `/passkey/update-passkey`, and `/passkey/delete-passkey`.
- Adds a `passkey` schema table with `userId`, `credentialID`, `publicKey`, `counter`, `deviceType`, `backedUp`, `transports`, `name`, `createdAt`, and `aaguid`.
- Stores WebAuthn challenges in the core verification table and references them through a signed temporary auth cookie.
- Stores credential public keys as strict Base64 strings so memory, SQL, and Rails adapters can persist the binary COSE public key consistently.
- Emits upstream-compatible registration/authentication option shapes, including `excludeCredentials`/`allowCredentials` descriptors with `type: "public-key"` and transport arrays.
- Supports v1.6 registration options: `registration.require_session: false`, `registration.resolve_user`, `registration.after_verification`, `registration.extensions`, and opaque registration `context`.
- Supports v1.6 authentication options: `authentication.extensions`, `authentication.after_verification`, array `origin` values, and authentication responses that include both `session` and `user`.
- Computes challenge expiration per request and rejects expired registration/authentication challenges.
- Returns upstream delete/update error behavior, including `PASSKEY_NOT_FOUND` for missing passkeys.

## Key Differences

- Ruby options use snake_case equivalents of upstream camelCase options, including `rp_id`, `rp_name`, `authenticator_selection`, and `advanced: { web_authn_challenge_cookie: ... }`.
- The `webauthn` gem exposes backup eligibility/backed-up flags but not SimpleWebAuthn's exact `credentialDeviceType` label, so Ruby maps backup-eligible credentials to `multiDevice` and all others to `singleDevice`.
- The core schema normalizes acronyms internally (`credentialId`), so passkey plugin responses convert back to upstream's public `credentialID` key.
- Browser client package aliases such as `authClient.passkey.*`, `returnWebAuthnResponse`, `useAutoRegister`, and conditional UI are TypeScript/browser client surface. Ruby server parity covers the underlying option/verification endpoints and callback behavior; a separate Ruby client/package extraction can be done later.
- Core `better_auth` keeps only a compatibility shim that raises a helpful install/require message when `better_auth-passkey` is missing.

## Testing

```bash
cd packages/better_auth-passkey
rbenv exec bundle exec ruby -Itest test/better_auth/passkey_test.rb
```

Key test file:

- `packages/better_auth-passkey/test/better_auth/passkey_test.rb`
