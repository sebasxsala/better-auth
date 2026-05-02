# Ruby SAML Upstream Parity Gaps Implementation Plan

> **For agentic workers:** Track progress with checkbox steps. Update this plan when a phase completes, when upstream differs materially from the Ruby implementation, or when a Ruby-specific adaptation is chosen.

**Goal:** Close the highest-impact SAML parity gaps against upstream Better Auth `upstream/packages/sso/src/saml.test.ts` at the repository's current `1.6.9` target.

**Architecture:** Keep `BetterAuth::Plugins.sso` as the public entrypoint while moving touched behavior into upstream-shaped `BetterAuth::SSO::*` helpers where practical. Use Better Auth Ruby core adapters, cookies, crypto, and endpoint context; do not introduce a separate SAML state store.

**Tech Stack:** Ruby 3.2+, Minitest, `ruby-saml`, `rexml`, Better Auth Ruby core.

---

## Status

- [x] Completed and verified.

## Upstream Parity Matrix

| Upstream `saml.test.ts` area | Ruby status | Notes |
| --- | --- | --- |
| Default SSO SAML provider lookup | Covered | Existing tests cover default SSO lookup and DB fallback. |
| Signed AuthnRequests | Covered | Ruby uses `ruby-saml` for Redirect signatures and private-key validation. |
| `idpMetadata` without XML fallback | Partial | This plan adds entityID, SSO, SLO, and cert fallback parsing. |
| Core SAML registration/login/metadata | Covered | Existing tests cover registration, metadata, login, size limits, and custom parser hooks. |
| RelayState generic-state flow | Partial | This plan replaces JWT RelayState with opaque verification-backed state while allowing ACS cross-site POST. |
| InResponseTo validation | Covered | Existing Ruby tests cover stored request consumption, mismatch, unknown, and unsolicited flows. |
| Account linking with `trustedProviders` | Not ported | This plan ports SAML linking to core social trust rules. |
| IdP-initiated callback redirects and open-redirect protection | Covered | Existing tests cover malicious RelayState, relative paths, and callback loop protection. |
| Timestamp validation | Covered | Existing tests cover skew, missing timestamps, malformed timestamps, and expiry. |
| Origin bypass for SAML endpoints | Covered | Existing tests cover SAML callback/ACS/SLO origin behavior and non-SAML protection. |
| Response security: unsigned, tampered, XSW, single assertion | Covered | Existing tests cover real `ruby-saml` validation and structural assertion guards. |
| Assertion replay protection | Covered | Existing tests cover replay and cross-provider replay. |
| Single Logout | Partial | Existing tests cover session storage, request/response routing, and safe redirects; this plan adds SLO signing flags. |
| `provisionUser` behavior | Covered | Existing tests cover new-user-only and every-login behavior. |
| ACS URL hardening todos in upstream | Intentionally different | Upstream keeps TODOs around callbackUrl/ACS split; Ruby preserves current public endpoint shape. |
| Registration-time config validation | Partial | Ruby validates entryPoint/metadata and size; this plan documents richer metadata fallback behavior. |

## Tasks

- [x] Create this follow-up plan document in `.docs/plans/`.
- [x] Add focused failing tests for opaque RelayState, SAML trusted-provider linking, IdP metadata parsing, and SLO signing flags.
- [x] Implement verification-backed RelayState helpers and use them for SAML sign-in and response parsing.
- [x] Port SAML account linking to upstream trust rules while preserving legacy `sso:<providerId>` account lookup compatibility.
- [x] Parse IdP metadata XML with `REXML` for entityID, signing certs, SSO services, SLO services, and binding preference.
- [x] Normalize and wire `want_logout_request_signed` / `want_logout_response_signed` options for Redirect-binding SLO signatures.
- [x] Move new helpers into upstream-shaped `BetterAuth::SSO::*` modules or delegate through those modules when keeping compatibility requires plugin methods.
- [x] Run targeted SAML tests, the full SSO suite, and `standardrb`.

## Ruby-Specific Notes

- `ruby-saml` is used for login AuthnRequest and Response validation, but SLO handling in this code path is lightweight. SLO Redirect signatures are implemented with the SAML Redirect binding query-string signature shape.
- ACS RelayState parsing intentionally does not require the relay-state cookie because IdP POST callbacks are usually cross-site and SameSite=Lax cookies are not sent.
- No gem version bump is included because this is not a release commit.
- Completion note: outbound Redirect-binding SLO requests and responses are signed when the new flags are enabled and a private key is configured. Incoming SLO signature enforcement remains documented as a `ruby-saml` limitation in this lightweight SLO path.
- Verification completed: targeted SAML tests, targeted `ruby-saml` tests, full `better_auth-sso` `rake test`, and `standardrb` all pass.
