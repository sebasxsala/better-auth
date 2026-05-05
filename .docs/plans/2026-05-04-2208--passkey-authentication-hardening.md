# Passkey Hardening Analysis Plan

**Goal:** Harden `better_auth-passkey` authentication challenge cleanup and credential uniqueness without changing route names, JSON wire keys, or callback signatures.

**Architecture:** Keep the upstream-compatible server route surface, add Ruby-specific cleanup and duplicate-credential safeguards inside the existing passkey route modules, and express the credential uniqueness invariant in the passkey schema so SQL adapters generate the correct constraint.

**Tech Stack:** Ruby 3.2+, `better_auth`, `better_auth-passkey`, `webauthn` gem, Minitest, StandardRB.

---

## Key Changes

- [x] Add authentication challenge cleanup after terminal failures once a valid challenge has been loaded, including missing passkey, callback errors, and failed session creation.
- [x] Preserve existing known `APIError` status/message behavior while keeping WebAuthn and argument errors mapped to `BAD_REQUEST` / `AUTHENTICATION_FAILED`.
- [x] Reject duplicate verified registration credential IDs with `BAD_REQUEST` / `PREVIOUSLY_REGISTERED` before creating a passkey row.
- [x] Change passkey schema `credentialID` from indexed to unique, and update SQL/schema tests to expect a unique constraint instead of a plain index.
- [x] Update README, docs, and changelog to document the uniqueness hardening and migration impact.

## Public API / Schema Impact

- [x] Route names, request bodies, response JSON keys, and callback signatures are unchanged.
- [x] The passkey schema changes: `credentialID` is unique instead of only indexed.
- [x] Existing databases need a migration that deduplicates historical duplicate `credential_id` rows before adding the unique constraint.
- [x] No version was bumped because this is an unreleased implementation change; bump the passkey gem only when preparing a release.

## Test Plan

- [x] Add an authentication route test proving a valid challenge is deleted when authentication fails with `PASSKEY_NOT_FOUND`.
- [x] Add tests for cleanup on `authentication.after_verification` raising and on failed session creation, preserving intended status/message behavior.
- [x] Add tests for cleanup on malformed authentication responses and unexpected passkey update errors after a challenge has been loaded.
- [x] Add registration tests proving duplicate credential IDs are rejected and no second passkey row is created.
- [x] Update schema tests to expect unique `credentialID` metadata and generated SQL unique constraint.
- [x] Run `rbenv exec bundle exec rake test` in `packages/better_auth-passkey`.
- [x] Run `rbenv exec bundle exec standardrb` in `packages/better_auth-passkey`.

## Assumptions

- [x] Use `.docs/plans/` per `AGENTS.md`.
- [x] Include the uniqueness change despite migration impact, because WebAuthn credential IDs should be globally unique per relying party.
- [x] Do not add the upstream browser client helper to the Ruby gem; the server-only scope remains intentional and documented.
