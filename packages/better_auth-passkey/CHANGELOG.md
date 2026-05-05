# Changelog

## [Unreleased]

- Require a fresh session for session-required passkey registration verification.
- Return `BAD_REQUEST` for passkey registration WebAuthn verification failures while preserving `INTERNAL_SERVER_ERROR` for unexpected failures.
- Invalidate stored WebAuthn challenges after failed registration or authentication verification attempts.
- Read passkey attestation metadata via the public `credential.response` API from the `webauthn` gem.

## [0.2.0] - 2026-04-29

- Aligned passkey registration, authentication, verification, origin handling, credential metadata, and route behavior with upstream Better Auth v1.6.9.
- Expanded passkey documentation and test coverage for upstream server parity.

## [0.1.0] - 2026-04-28

- Initial external passkey package extracted from `better_auth`.
