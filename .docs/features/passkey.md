# Feature: Passkey Plugin

**Upstream Reference:** `upstream/packages/passkey/src/index.ts`, `upstream/packages/passkey/src/routes.ts`, `upstream/packages/passkey/src/schema.ts`, `upstream/packages/passkey/src/passkey.test.ts`

## Summary

Adds passkey/WebAuthn registration, authentication, listing, renaming, and deletion through the upstream passkey route contract.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.passkey`.
- Uses the maintained `webauthn` gem (`cedarcode/webauthn-ruby`) for WebAuthn option generation, attestation verification, assertion verification, signature checks, origin checks, RP ID checks, and sign-count checks.
- Adds `/passkey/generate-register-options`, `/passkey/verify-registration`, `/passkey/generate-authenticate-options`, `/passkey/verify-authentication`, `/passkey/list-user-passkeys`, `/passkey/update-passkey`, and `/passkey/delete-passkey`.
- Adds a `passkey` schema table with `userId`, `credentialID`, `publicKey`, `counter`, `deviceType`, `backedUp`, `transports`, `name`, `createdAt`, and `aaguid`.
- Stores WebAuthn challenges in the core verification table and references them through a signed temporary auth cookie.
- Stores credential public keys as strict Base64 strings so memory, SQL, and Rails adapters can persist the binary COSE public key consistently.

## Key Differences

- Ruby options use snake_case equivalents of upstream camelCase options, including `rp_id`, `rp_name`, `authenticator_selection`, and `advanced: { web_authn_challenge_cookie: ... }`.
- The `webauthn` gem exposes backup eligibility/backed-up flags but not SimpleWebAuthn's exact `credentialDeviceType` label, so Ruby maps backup-eligible credentials to `multiDevice` and all others to `singleDevice`.
- The core schema normalizes acronyms internally (`credentialId`), so passkey plugin responses convert back to upstream's public `credentialID` key.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/passkey_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/passkey_test.rb`
