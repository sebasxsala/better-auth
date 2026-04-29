# Extract Passkey To `better_auth-passkey`

## Summary

Move passkey/WebAuthn support from core `better_auth` into an external `better_auth-passkey` package, matching upstream's separate `@better-auth/passkey` boundary. Core keeps only a compatibility shim for `BetterAuth::Plugins.passkey`.

## Steps

- [x] Add failing core shim coverage for missing `better_auth/passkey`.
- [x] Add failing upstream parity coverage for invalid `registration.after_verification` `user_id` overrides.
- [x] Create `packages/better_auth-passkey` with gemspec, entrypoint, version, README, changelog, Rakefile, and test helper.
- [x] Move the passkey implementation and Minitest/WebAuthn tests into the external package.
- [x] Replace the core passkey implementation with a helpful external-package shim.
- [x] Remove the core runtime dependency on `webauthn`; add it to `better_auth-passkey`.
- [x] Move passkey schema/SQL coverage out of core and keep Rails migration coverage behind `require "better_auth/passkey"`.
- [x] Add `better_auth-passkey` to workspace Rake tasks, CI, release workflow, release docs, and parity docs.
- [x] Run focused package/core/Rails verification.
- [x] Run broader package CI verification where practical.

## Ruby-Specific Decisions

- Keep the public API as `BetterAuth::Plugins.passkey`.
- Use `require "better_auth/passkey"` as the explicit external package entrypoint.
- Keep browser-client passkey helpers out of Ruby scope.
- Prefer real `WebAuthn::FakeClient` integration tests over upstream's mocked SimpleWebAuthn server tests.
