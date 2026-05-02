# SSO Upstream Parity Implementation Plan

> **For agentic workers:** Track progress with checkbox steps. Update this plan when a phase completes, when upstream differs materially from the Ruby implementation, or when a Ruby-specific adaptation is chosen.

**Goal:** Bring `packages/better_auth-sso` to upstream SSO v1.6.9 parity, with SAML working end to end.

**Architecture:** Keep `BetterAuth::Plugins.sso` as the public entrypoint, but move behavior into focused `BetterAuth::SSO` modules that mirror upstream `src/`, `src/linking`, `src/oidc`, `src/routes`, and `src/saml`. Use `better_auth` core services (`BetterAuth::Crypto`, `Endpoint`, `Routes`, `Cookies`, adapters, hooks) instead of package-local replacements.

**Tech Stack:** Ruby 3.2+, Minitest, `ruby-saml`, `jwt`, Better Auth Ruby core.

---

## Tasks

- [x] Create this plan document in `.docs/plans/` before implementation.
- [x] Capture the failing SSO baseline and use it as the first regression target.
- [x] Normalize SAML body/query/params key handling for upstream `SAMLResponse`, `SAMLRequest`, and `RelayState` inputs.
- [x] Fix custom SAML parser invocation so opaque non-XML values are passed through unchanged and base64 XML still gets single-assertion validation.
- [x] Fix RelayState and InResponseTo validation so SP-initiated callbacks redirect to the signed callback URL and consume matching request records.
- [x] Fix SAML replay protection, timestamp validation, response validation hook ordering, and custom parser error behavior.
- [x] Fix SLO request/response routing, status validation, pending request storage, session cleanup, safe redirects, and POST-form behavior.
- [x] Fix real `ruby-saml` request/response validation against signed assertions, audience, recipient, destination, issuer, timestamps, and algorithms.
- [x] Replace ad hoc randomness with `BetterAuth::Crypto.random_string` where SSO generates upstream-equivalent random values.
- [x] Split the current monolithic SSO plugin into focused Ruby modules under `lib/better_auth/sso/`, preserving public API compatibility.
- [x] Add or translate upstream parity tests for utils, OIDC discovery, providers, domain verification, org linking, SAML algorithms, assertions, timestamps, SAML pipeline, SLO, and `ruby-saml`.
- [x] Run targeted SSO test files, the full SSO suite, and `standardrb`.

## Notes

- Current baseline from 2026-05-01: `rbenv exec bundle exec rake test` in `packages/better_auth-sso` fails with 14 failures and 3 errors.
- Ruby-specific adaptation: `better-auth/crypto` imports map to `BetterAuth::Crypto`; no monorepo import shim is needed.
- Existing unrelated dirty worktree changes outside `packages/better_auth-sso` and this plan are intentionally ignored.
- Completion note: the primary root cause was case-sensitive SAML payload lookup. Normalizing fetch semantics fixed custom parser input, RelayState, InResponseTo, SLO branch selection, and real `ruby-saml` callback validation. The new module files provide upstream-shaped Ruby namespaces while delegating to the now-green implementation to preserve compatibility.
