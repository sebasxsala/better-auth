# SSO Upstream File Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the Ruby SSO package toward Better Auth upstream `packages/sso` parity by matching upstream structure and tests nearly file-by-file.

**Architecture:** Keep `ruby-saml` as the low-level SAML engine for XML parsing, AuthnRequest/Response handling, signature/certificate work, metadata handling where reliable, and SAML protocol primitives. Better Auth Ruby owns the product/security layers above it: RelayState storage, replay protection, timestamp policy, algorithm policy, account linking trust rules, callback safety, provider lookup, SLO behavior, error mapping, and parity tests. Do not rewrite a full SAML engine unless a specific upstream parity test proves `ruby-saml` cannot support the behavior.

**Tech Stack:** Ruby 3.2+, Minitest, `better_auth`, `better_auth-sso`, `ruby-saml`, upstream Better Auth `v1.6.9` TypeScript source under `upstream/packages/sso/src`.

---

## Scope

- [x] Use `upstream/packages/sso/src` at Better Auth `v1.6.9` as source of truth.
- [x] Preserve public Ruby plugin entrypoint `BetterAuth::Plugins.sso`.
- [x] Preserve existing SSO/SAML endpoint paths unless upstream requires an intentional compatibility note.
- [x] Keep `ruby-saml` as the low-level SAML protocol dependency.
- [x] Add Ruby-owned layers where upstream behavior is outside `ruby-saml`.
- [x] Keep legacy Ruby compatibility paths where they already exist, and document intentional differences.
- [x] Do not bump gem versions unless this work is explicitly released.

## Upstream Source Checklist

### Package Entrypoints

- [x] Port structure for `upstream/packages/sso/src/index.ts`.
- [x] Port structure for `upstream/packages/sso/src/client.ts`.
- [x] Port structure for `upstream/packages/sso/src/constants.ts`.
- [x] Port structure for `upstream/packages/sso/src/types.ts`.
- [x] Port structure for `upstream/packages/sso/src/version.ts`.

### Shared Utilities

- [x] Port structure for `upstream/packages/sso/src/utils.ts`.
- [x] Port tests from `upstream/packages/sso/src/utils.test.ts`.

### Domain Verification

- [x] Port structure for `upstream/packages/sso/src/routes/domain-verification.ts`.
- [x] Port tests from `upstream/packages/sso/src/domain-verification.test.ts`.

### Provider Routes

- [x] Port structure for `upstream/packages/sso/src/routes/providers.ts`.
- [x] Port structure for `upstream/packages/sso/src/routes/schemas.ts`.
- [x] Port tests from `upstream/packages/sso/src/providers.test.ts`.

### SSO Routes

- [x] Port structure for `upstream/packages/sso/src/routes/sso.ts`.
- [x] Port structure for `upstream/packages/sso/src/routes/helpers.ts`.
- [x] Port structure for `upstream/packages/sso/src/routes/saml-pipeline.ts`.

### OIDC

- [x] Port structure for `upstream/packages/sso/src/oidc/index.ts`.
- [x] Port structure for `upstream/packages/sso/src/oidc/types.ts`.
- [x] Port structure for `upstream/packages/sso/src/oidc/errors.ts`.
- [x] Port structure for `upstream/packages/sso/src/oidc/discovery.ts`.
- [x] Port tests from `upstream/packages/sso/src/oidc.test.ts`.
- [x] Port tests from `upstream/packages/sso/src/oidc/discovery.test.ts`.

### Account Linking

- [x] Port structure for `upstream/packages/sso/src/linking/index.ts`.
- [x] Port structure for `upstream/packages/sso/src/linking/types.ts`.
- [x] Port structure for `upstream/packages/sso/src/linking/org-assignment.ts`.
- [x] Port tests from `upstream/packages/sso/src/linking/org-assignment.test.ts`.

### SAML Engine Boundary

- [x] Port the boundary role of `upstream/packages/sso/src/samlify.ts` into a Ruby adapter backed by `ruby-saml`.
- [x] Keep AuthnRequest generation delegated to `ruby-saml` where possible.
- [x] Keep SAML Response parsing delegated to `ruby-saml` where possible.
- [x] Keep XML signature, certificate, and metadata protocol behavior delegated to `ruby-saml` where possible.
- [x] Add Ruby-owned wrappers when upstream semantics need behavior not exposed directly by `ruby-saml`.

### SAML State

- [x] Port structure for `upstream/packages/sso/src/saml-state.ts`.

### SAML Core

- [x] Port structure for `upstream/packages/sso/src/saml/index.ts`.
- [x] Port structure for `upstream/packages/sso/src/saml/algorithms.ts`.
- [x] Port structure for `upstream/packages/sso/src/saml/assertions.ts`.
- [x] Port structure for `upstream/packages/sso/src/saml/error-codes.ts`.
- [x] Port structure for `upstream/packages/sso/src/saml/parser.ts`.
- [x] Port structure for `upstream/packages/sso/src/saml/timestamp.ts`.
- [x] Port tests from `upstream/packages/sso/src/saml/algorithms.test.ts`.
- [x] Port tests from `upstream/packages/sso/src/saml/assertions.test.ts`.
- [x] Port tests from `upstream/packages/sso/src/saml.test.ts`.

## Ruby Target Structure

### Public Entrypoints

- [x] Keep `packages/better_auth-sso/lib/better_auth/plugins/sso.rb` as the public plugin entrypoint.
- [x] Move SSO route orchestration out of the monolithic plugin where practical.
- [x] Keep `packages/better_auth-sso/lib/better_auth/sso.rb` as the package-level loader.
- [x] Keep `packages/better_auth-sso/lib/better_auth/sso/version.rb` unchanged unless releasing.

### Shared Ruby Modules

- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/constants.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/types.rb` only if Ruby needs a shared type/config normalization module.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/utils.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/domain_verification.rb`.

### Provider and Route Modules

- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/routes/providers.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/routes/schemas.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/routes/sso.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/routes/helpers.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/routes/saml_pipeline.rb`.

### OIDC Modules

- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/oidc.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/oidc/discovery.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/oidc/errors.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/oidc/types.rb`.

### Linking Modules

- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/linking.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/linking/types.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/linking/org_assignment.rb`.

### SAML Modules

- [x] Keep or update `packages/better_auth-sso/lib/better_auth/sso/saml.rb` as the `ruby-saml` engine adapter.
- [x] Keep or update `packages/better_auth-sso/lib/better_auth/sso/saml_state.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/saml/algorithms.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/saml/assertions.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/saml/error_codes.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/saml/parser.rb`.
- [x] Create or update `packages/better_auth-sso/lib/better_auth/sso/saml/timestamp.rb`.

## Ruby-Owned Behavior Above `ruby-saml`

- [x] Implement upstream-style RelayState generation, storage, parsing, expiry, and callback priority in Ruby-owned code.
- [x] Implement replay protection in Ruby-owned code.
- [x] Implement timestamp policy in Ruby-owned code.
- [x] Implement algorithm allow/deny/deprecated policy in Ruby-owned code.
- [x] Implement single-assertion and wrapping-attack checks in Ruby-owned code.
- [x] Implement SAML account linking trust rules in Ruby-owned code.
- [x] Implement provider lookup, default provider fallback, and DB provider fallback in Ruby-owned code.
- [x] Implement safe callback URL and open-redirect protection in Ruby-owned code.
- [x] Implement SLO request/response orchestration in Ruby-owned code, delegating XML/protocol primitives to `ruby-saml` when available.
- [x] Implement upstream error-code mapping in Ruby-owned code.
- [x] Document any behavior that is intentionally different because of Ruby compatibility or `ruby-saml` limitations.

## Ruby Test Checklist

### Existing Test Files

- [x] Expand `packages/better_auth-sso/test/better_auth/sso_test.rb`.
- [x] Expand `packages/better_auth-sso/test/better_auth/sso_saml_test.rb`.
- [x] Expand `packages/better_auth-sso/test/better_auth/sso_ruby_saml_test.rb`.

### New Test Files Mirroring Upstream

- [x] Create `packages/better_auth-sso/test/better_auth/sso_structure_test.rb` for loader/module skeleton coverage.
- [x] Create `packages/better_auth-sso/test/better_auth/sso/structure_contract_test.rb` for constants/types/OIDC surface coverage.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/utils_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/domain_verification_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/providers_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/routes/helpers_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/routes/sso_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/routes/saml_pipeline_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/routes/schemas_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/oidc_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/oidc/discovery_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/linking/org_assignment_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/saml_adapter_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/saml_state_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/saml/algorithms_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/saml/assertions_test.rb`.
- [x] Create or update `packages/better_auth-sso/test/better_auth/sso/saml_test.rb`.

## Execution Order

## Initial Parity Matrix

| Upstream test file | Upstream describe/it count | Ruby target | Ruby status | Notes |
| --- | ---: | --- | --- | --- |
| `upstream/packages/sso/src/client.ts` | N/A | `packages/better_auth-sso/test/better_auth/sso_structure_test.rb` | Covered | Added Ruby `SSO::Client.sso_client` contract for client id, package version, inferred domain-verification flag, and the upstream path-method map. |
| `upstream/packages/sso/src/version.ts` | N/A | `packages/better_auth-sso/test/better_auth/sso_structure_test.rb` | Covered | Added `BetterAuth::SSO::PACKAGE_VERSION` as the Ruby alias for the package version export without changing the gem version. |
| `upstream/packages/sso/src/utils.test.ts` | 26 | `packages/better_auth-sso/test/better_auth/sso/utils_test.rb` | Covered | Ported focused `validateEmailDomain`, `domainMatches`, `getHostnameFromDomain`, `parseCertificate`, `maskClientId`, and Ruby `safe_json_parse` coverage for the upstream `safeJsonParse` behavior used by SSO config parsing; describe blocks are represented as Minitest methods. Ruby computes certificate SHA-256 fingerprints from DER and exposes snake_case keys. |
| `upstream/packages/sso/src/domain-verification.test.ts` | 23 | `packages/better_auth-sso/test/better_auth/sso/domain_verification_test.rb` | Covered | Added mirrored request/verify endpoint coverage for missing session, missing provider, owner/org access, active and expired tokens, verified-domain conflicts, custom token prefix, bare domains, DNS failure, secondary storage, and provider registration token creation. Ruby keeps the injectable DNS resolver; provider registration now creates the verification token like upstream. |
| `upstream/packages/sso/src/providers.test.ts` | 46 | `packages/better_auth-sso/test/better_auth/sso/providers_test.rb` | Covered | Mirrored read/update/delete behavior in 34 Ruby tests, with a few upstream cases combined where they share setup. Covered auth errors, missing providers, owner and org-admin access, non-admin denial, owned providers with org IDs when org plugin is disabled, org-admin precedence when enabled, DB-serialized OIDC/SAML config sanitization and update merging, secret/cert hiding, certificate parse errors, short client ID masking, domain verification reset, invalid issuer/no-op update errors, config type mismatch errors, delete success/404-after-delete, and linked accounts surviving provider deletion. Ruby now parses serialized provider configs from DB before sanitizing or merging updates. |
| `upstream/packages/sso/src/oidc.test.ts` | 30 | `packages/better_auth-sso/test/better_auth/sso/oidc_test.rb` | Covered | Added 13 mirrored Ruby tests covering registration, safe mapping return, invalid issuer, duplicate provider IDs, email/domain/providerId/org slug sign-in, runtime discovery hydration, lowercase email reuse, disabled implicit signup with requested signup, provisioning hooks, shared redirect URI, defaultSSO provider/email matching, defaultSSO runtime discovery, and UserInfo `sub` fallback. Existing deeper token/JWKS/state behavior remains covered in `sso_oidc_test.rb`. Ruby intentionally returns sanitized provider registration data while storing the full OIDC config and still hides `clientSecret`. |
| `upstream/packages/sso/src/oidc/discovery.test.ts` | 82 | `packages/better_auth-sso/test/better_auth/sso/oidc/discovery_test.rb` | Covered | Ported discovery URL/document/normalization/auth-method/runtime-needed plus fetch/discover/ensureRuntimeDiscovery cases with injected fetch. |
| `upstream/packages/sso/src/oidc/types.ts` | N/A | `packages/better_auth-sso/test/better_auth/sso/structure_contract_test.rb` | Covered | Added Ruby `OIDC::Types` constants for discovery required fields and discovery error codes, delegating behavior to the existing discovery/error modules. |
| `upstream/packages/sso/src/linking/org-assignment.test.ts` | 9 | `packages/better_auth-sso/test/better_auth/sso/linking/org_assignment_test.rb` | Covered | Ported upstream domain assignment cases with a focused fake adapter. Ruby `OrgAssignment` now owns the upstream structure for provider-based and domain-based org assignment, including organization plugin checks, provisioning disable, `defaultRole`, `getRole`, `profile.rawAttributes`, token handoff, exact-domain fast lookup, comma-separated domain fallback, verified-domain filtering, duplicate membership avoidance, and legacy `config:` compatibility. |
| `upstream/packages/sso/src/linking/types.ts` | N/A | `packages/better_auth-sso/test/better_auth/sso/structure_contract_test.rb` | Covered | Added Ruby `Linking::Types.normalized_profile` for the upstream `NormalizedSSOProfile` shape, accepting camelCase and snake_case keys while preserving `rawAttributes` as opaque caller data. |
| `upstream/packages/sso/src/saml-state.ts` | N/A | `packages/better_auth-sso/test/better_auth/sso/saml_state_test.rb` | Covered | Added focused module tests for `generate_relay_state` and `parse_relay_state`: required `callbackURL`, upstream `link` payload, optional `additionalData: false`, stored opaque RelayState, code verifier, expiry, cookie write, and ACS-style parse without requiring the cookie. |
| `upstream/packages/sso/src/saml/index.ts` | N/A | `packages/better_auth-sso/test/better_auth/sso/structure_contract_test.rb` | Covered | Added root `SSO::SAML` wrapper exports for config algorithm validation, SAML XML algorithm validation, and single-assertion validation, delegating to the existing Ruby modules. |
| `upstream/packages/sso/src/saml/algorithms.test.ts` | 46 | `packages/better_auth-sso/test/better_auth/sso/saml/algorithms_test.rb` | Covered | Ported response/config algorithm validation, constants, short-form names, allow-lists, deprecated handling, and encryption cases. |
| `upstream/packages/sso/src/saml/assertions.test.ts` | 26 | `packages/better_auth-sso/test/better_auth/sso/saml/assertions_test.rb` | Covered | Ported all upstream assertion validation, namespace, count, invalid base64, and non-XML cases. |
| `upstream/packages/sso/src/saml.test.ts` | 108 `it`, 147 `describe`/`it` | `packages/better_auth-sso/test/better_auth/sso/saml_test.rb`, `packages/better_auth-sso/test/better_auth/sso_saml_test.rb`, `packages/better_auth-sso/test/better_auth/sso_ruby_saml_test.rb`, `packages/better_auth-sso/test/better_auth/sso/utils_test.rb`, `packages/better_auth-sso/test/better_auth/sso/providers_test.rb` | Covered | Created the upstream-shaped `saml_test.rb` mirror with 71 Ruby tests for defaultSSO SAML selection, signed AuthnRequest URL fields, signed AuthnRequest signature verification, unsigned AuthnRequest URL fields, missing private key errors, partial `idpMetadata` fallback to top-level config, XML `idpMetadata` parsing for entity ID/cert/SSO/SLO services, login entryPoint derivation from metadata, SAML provider registration sanitization, nested safe `idpMetadata`/`spMetadata`/mapping config return without private-key leaks, duplicate provider rejection, provider limit rejection including function limits, explicit `spMetadata.metadata` return, generated SP metadata issuer/callback/NameIDFormat output, providerId-derived ACS URL hardening when callbackUrl is an app destination, opaque verification-backed RelayState, callback and ACS cross-site POST without cookie, invalid RelayState fallback, RelayState callback priority, IdP-initiated GET-after-POST redirect handling with session, GET-after-callback-loop fallback to base URL, direct GET without session error redirect, GET RelayState open-redirect blocking, raw relative and protocol-relative RelayState fallback behavior, SAML callback/ACS loop prevention, origin-check bypass for SAML callback/ACS/SLO and metadata while preserving non-SAML CSRF blocking, RelayState open-redirect blocking under origin bypass, `disableImplicitSignUp` requestSignUp allow/deny behavior on callback and ACS, SAML account linking denied/allowed by `trustedProviders`, verified-domain SAML account linking, legacy `sso:<providerId>` account lookup compatibility, SAML `provision_user` first-login/every-login behavior, provider lookup fallback with configured `default_sso`, unknown provider 404 behavior, registration-time invalid/missing `entryPoint` validation, unsolicited SAML response allow/deny behavior, disabled `InResponseTo` validation, verification-table request ID validation/deletion, unknown request ID and provider mismatch errors, raw RelayState open-redirect blocking, timestamp validation edge cases, SAML size limits, single assertion/XSW checks, replay rejection across callback and ACS, lowercase email reuse, SLO disabled and provider-not-found errors, SLO metadata, SP-initiated SLO request generation and stored NameID/session index, IdP-initiated LogoutRequest session cleanup, LogoutResponse pending-request consumption, missing/malicious RelayState safe SLO redirects, and failed LogoutResponse retention. Legacy `sso_saml_test.rb` and `sso_ruby_saml_test.rb` cover real signed/unsigned/tampered SAML response behavior through `ruby-saml`; `utils_test.rb` and `providers_test.rb` cover the upstream `safeJsonParse` and serialized config parsing cases embedded in `saml.test.ts`. |

### `saml.test.ts` Case Matrix

| Upstream area / line range | Upstream cases | Ruby status | Ruby coverage notes |
| --- | ---: | --- | --- |
| Default SAML provider selection, lines 648-662 | 1 | Covered | `saml_test.rb` covers configured `default_sso` array selection when the DB has no matching provider. |
| Signed AuthnRequests, lines 742-837 | 4 | Covered | `saml_test.rb` covers signature fields, RelayState inclusion, IdP-verifiable Redirect binding signatures, and missing private key rejection. |
| Unsigned AuthnRequests, lines 885-902 | 1 | Covered | `saml_test.rb` verifies unsigned URLs omit `Signature` and `SigAlg`. |
| `idpMetadata` fallback and XML parsing, lines 956-991 | 2 | Covered | `saml_test.rb` covers top-level fallback and metadata entity ID preference. |
| Provider registration, metadata, limits, login, RelayState, signup, linking, unsolicited responses, and InResponseTo validation, lines 1071-2600 | 24 | Covered | `saml_test.rb` mirrors the endpoint cases; broader legacy endpoint behavior remains in `sso_saml_test.rb`. |
| Custom fields and provider config parsing, lines 2743-2978 | 10 | Covered | `saml_test.rb` covers nested SAML config sanitization; `providers_test.rb` covers serialized SAML/OIDC DB configs avoiding `[object Object]`; `utils_test.rb` covers object/string/nil/blank/invalid/empty-object parsing. Ruby maps upstream `undefined` to `nil`. |
| IdP-initiated GET flow and redirect hardening, lines 2990-3651 | 9 | Covered | `saml_test.rb` covers GET-after-POST, direct GET without session, callback loop prevention, query RelayState, malicious RelayState, relative path fallback, and protocol-relative blocking. Ruby intentionally falls back to provider/base callback for raw relative RelayState instead of treating it as an app-relative redirect. |
| Timestamp validation, lines 3655-3879 | 23 | Covered | `saml_test.rb` groups all timestamp windows, boundary, missing, custom skew, malformed, empty-string, garbage, and ISO cases through the Ruby timestamp policy wrapper. |
| ACS origin bypass, lines 3884-4094 | 5 | Covered | `saml_test.rb` covers callback/ACS/SLO cross-site POST bypasses, metadata GET, non-SAML CSRF preservation, and malicious RelayState blocking under bypass. |
| SAML response security, lines 4096-4198 | 2 | Covered | `sso_ruby_saml_test.rb` verifies unsigned forged responses and tampered signed NameID are rejected by the real `ruby-saml` adapter boundary. |
| Size limits, lines 4205-4213 | 1 | Covered | `saml_test.rb` and `sso_saml_test.rb` cover upstream default response/metadata size limits. |
| Replay protection, lines 4215-4454 | 3 | Covered | `saml_test.rb` covers replay rejection on callback, ACS, and cross-endpoint reuse. |
| Single assertion validation, lines 4456-4801 | 5 | Covered | `saml_test.rb` covers zero, multiple, ACS multiple, XSW injection, and exactly-one valid assertion behavior. |
| Lowercase email normalization, lines 4803-4954 | 1 | Covered | `saml_test.rb` verifies lowercase reuse and duplicate prevention. |
| Single Logout, lines 4977-5469 | 10 | Covered | `saml_test.rb` covers disabled/provider missing errors, CSRF bypass, metadata SLO inclusion/exclusion, missing IdP SLO service, generated LogoutRequest, LogoutRequest cleanup, LogoutResponse relay/base redirects, and failure retention. |
| Provisioning hooks, lines 5552-5769 | 2 | Covered | `saml_test.rb` covers `provision_user` first-login behavior and `provision_user_on_every_login`. |
| Hardening provider fallback, registration validation, and RelayState priority, lines 5872-6049 | 4 | Covered | `saml_test.rb` covers DB provider preference over `default_sso`, unknown provider 404, empty `entryPoint` rejection without metadata, and RelayState callback priority. |

### Intentional Ruby Differences

- Ruby keeps `BetterAuth::Plugins.sso` and existing endpoint paths as compatibility surfaces while adding upstream-shaped modules under `BetterAuth::SSO`.
- Ruby delegates XML protocol parsing, AuthnRequest/Response validation, signatures, certificates, and metadata primitives to `ruby-saml`; Better Auth Ruby owns policy wrappers for RelayState, replay, timestamps, algorithms, account linking, callback safety, SLO orchestration, and error mapping.
- Upstream `undefined` inputs map to Ruby `nil`; blank strings are treated as absent for Ruby compatibility where existing callers already rely on that behavior.
- Upstream camelCase public data is preserved at API boundaries, while Ruby module internals use snake_case and normalize both forms on input.
- Raw relative `RelayState` values fall back to provider/base callback URLs unless they came from the stored verification RelayState flow; this preserves legacy open-redirect hardening while the generated RelayState callback URL still takes upstream priority.
- `BetterAuth::Plugins.sso` remains the public plugin surface, but practical route orchestration now delegates endpoint map construction to `BetterAuth::SSO::Routes::SSO.endpoints` and plugin schema construction to `BetterAuth::SSO::Routes::Schemas.plugin_schema`. A deeper extraction of individual endpoint bodies can be handled as a separate refactor.

### Phase 1: Inventory and Matrix

- [x] Count upstream `describe` / `it` / `it.todo` blocks per upstream test file.
- [x] Count Ruby tests per target Ruby test file.
- [x] Create a parity matrix grouped by upstream file.
- [x] Mark each upstream test case as `covered`, `partial`, `not ported`, or `intentionally different`.
- [ ] Commit only the matrix and plan updates.

### Phase 2: Module Skeleton Parity

- [x] Create Ruby module files that match the upstream structure.
- [x] Keep public behavior delegated through existing plugin entrypoint.
- [x] Add loader requires for new Ruby modules.
- [x] Run existing SSO tests.
- [ ] Commit module skeletons.

### Phase 3: Test Port

- [x] Port upstream tests file-by-file.
- [x] For each upstream test file, add Ruby tests before changing implementation.
- [x] Mark unsupported upstream tests as pending only with a written reason.
- [x] Run the focused Ruby test file after each port.
- [ ] Commit each upstream test file port separately.

### Phase 4: Behavior Port

- [x] Implement only the code needed to pass the newly ported tests.
- [x] Keep `ruby-saml` behind the SAML adapter boundary.
- [x] Add Ruby-owned policy layers around `ruby-saml` instead of changing endpoint behavior ad hoc.
- [x] Update the parity matrix when behavior is covered or intentionally different.
- [ ] Commit behavior by upstream module area.

### Phase 5: Final Parity Verification

- [x] Run `rbenv exec bundle exec ruby -Itest test/better_auth/sso_saml_test.rb`.
- [x] Run `rbenv exec bundle exec ruby -Itest test/better_auth/sso_ruby_saml_test.rb`.
- [x] Run every new mirrored SSO test file.
- [x] Run `rbenv exec bundle exec rake test`.
- [x] Run `rbenv exec bundle exec standardrb`.
- [x] Confirm the parity matrix has no unreviewed upstream tests.
- [ ] Commit final matrix and cleanup.

Verification results from `packages/better_auth-sso`:

- `rbenv exec bundle exec ruby -Itest test/better_auth/sso_saml_test.rb`: 40 runs, 194 assertions, 0 failures.
- `rbenv exec bundle exec ruby -Itest test/better_auth/sso_ruby_saml_test.rb`: 9 runs, 48 assertions, 0 failures.
- `rbenv exec bundle exec ruby -Itest -e 'ARGV.each { |file| load file }' $(rg --files test/better_auth/sso test/better_auth/sso_structure_test.rb | sort)`: 343 runs, 1042 assertions, 0 failures.
- `rbenv exec bundle exec ruby -Itest -e 'ARGV.each { |file| load file }' test/better_auth/sso/routes/sso_test.rb test/better_auth/sso/routes/schemas_test.rb`: 11 runs, 84 assertions, 0 failures.
- `rbenv exec bundle exec rake test`: 427 runs, 1477 assertions, 0 failures.
- `rbenv exec bundle exec standardrb`: passed.

## Commit Strategy

- [ ] Commit plan and matrix updates separately from code.
- [ ] Commit module skeletons separately from behavior.
- [ ] Commit each upstream test file port separately when practical.
- [ ] Commit each implementation area after focused tests pass.
- [ ] Do not include unrelated dirty worktree changes.
