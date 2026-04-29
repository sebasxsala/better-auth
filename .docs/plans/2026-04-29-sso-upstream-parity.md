# SSO Upstream Parity Plan

Upstream reference: `upstream/packages/sso` at submodule commit `f484269228b7eb8df0e2325e7d264bb8d7796311`.

Ruby target package: `packages/better_auth-sso`.

Goal: bring the Ruby SSO package to behavioral, API, and test parity with the upstream Better Auth SSO package. Upstream behavior is the source of truth; Ruby adaptations should stay idiomatic but preserve public semantics.

## Current High-Risk Gaps

- [x] Replace the default Ruby SAML JSON parser path with real SAML XML processing. Upstream validates base64 SAML XML through single-assertion checks, samlify parsing, algorithm checks, timestamp validation, replay protection, and session creation. Ruby no longer accepts base64 JSON by default in `sso_parse_saml_response`.
- [x] Implement SAML AuthnRequest/InResponseTo correlation. Upstream stores AuthnRequest IDs during SAML sign-in and validates unknown, expired, and provider-mismatched responses.
- [x] Enforce domain verification on SSO sign-in when `domainVerification.enabled` is true. Callback enforcement still needs to be completed.
- [x] Replace Ruby's provider-scoped, fixed-300-second SAML replay keying with upstream-style assertion ID replay tracking using assertion expiry or default TTL.
- [ ] Add SAML Single Logout support: SLO metadata, `/sso/saml2/sp/slo/:providerId`, `/sso/saml2/logout/:providerId`, SP-initiated logout, IdP-initiated logout, LogoutResponse handling, session lookup records, and SLO origin bypass. Core unsigned flows, upstream-style session lookup records, POST form response, IdP metadata SLO URL extraction, safe LogoutResponse RelayState handling, and non-success LogoutResponse rejection are implemented; signed request/response validation still needs deeper parity.

## Plugin/API Surface Differences

- [ ] Export Ruby equivalents for upstream public helpers/constants where appropriate: SSO types/options, OIDC discovery helpers, SAML timestamp validation, SAML algorithm constants/options, and max-size/default constants.
- [ ] Add missing endpoint surface:
  - [x] `callbackSSOShared` equivalent at `GET /sso/callback`.
  - [x] `sloEndpoint` equivalent at `/sso/saml2/sp/slo/:providerId`.
  - [x] `initiateSLO` equivalent at `/sso/saml2/logout/:providerId`.
- [ ] Gate domain verification endpoints and `domainVerified` schema additions behind `domainVerification.enabled`. Ruby currently always registers these endpoints and fields.
- [ ] Decide whether Ruby needs a client-side companion API comparable to upstream `ssoClient` path methods for `/sso/providers` and `/sso/get-provider`.
- [x] Add SLO paths to the origin-check bypass list. Ruby currently bypasses SAML callback, ACS, and SLO paths.

## Options Differences

- [ ] Add upstream option support:
  - [x] `provisionUser`
  - [x] `provisionUserOnEveryLogin`
  - [ ] `organizationProvisioning.disabled`
  - [ ] `organizationProvisioning.defaultRole`
  - [ ] `organizationProvisioning.getRole`
  - [x] `defaultSSO` for OIDC sign-in provider selection.
  - [x] `defaultOverrideUserInfo`
  - [x] `disableImplicitSignUp`
  - [ ] `modelName`
  - [ ] `fields`
  - [ ] `providersLimit`
  - [x] `trustEmailVerified`
  - [ ] `domainVerification.tokenPrefix`
  - [x] shared/custom `redirectURI` for OIDC authorization URLs.
- [ ] Add upstream SAML option support:
  - [x] `enableInResponseToValidation`
  - [ ] `allowIdpInitiated`
  - [ ] `requestTTL`
  - [x] `clockSkew`
  - [x] `requireTimestamps`
  - [x] `maxMetadataSize`
  - [x] `maxResponseSize`
  - [ ] `algorithms.onDeprecated`
  - [ ] signature/digest/key-encryption/data-encryption allow-lists
  - [x] `enableSingleLogout`
  - [ ] `wantLogoutRequestSigned`
  - [ ] `wantLogoutResponseSigned`
- [ ] Align snake_case Ruby option names with upstream camelCase request/config names at the public API boundary, while preserving Ruby ergonomics internally.

## Route and Endpoint Differences

- [x] Add upstream-compatible provider management routes:
  - [x] `GET /sso/get-provider`
  - [x] `POST /sso/update-provider`
  - [x] `POST /sso/delete-provider`
- [ ] Decide whether to retain Ruby REST-style aliases `GET/PATCH/DELETE /sso/providers/:providerId` as compatibility extensions after upstream routes are added.
- [x] Add shared OIDC callback `GET /sso/callback`, resolving provider ID from OAuth state when `redirectURI` is configured.
- [ ] Add SAML GET callback behavior. Upstream treats GET callback as a post-login redirect requiring an existing session and safe RelayState handling; Ruby currently sends GET through full SAML response handling.
- [x] Make SP metadata response XML derived from provider config instead of a static placeholder; include ACS, optional SingleLogoutService, and signing flags. NameID format still needs deeper metadata parity.

## Schema/Model Differences

- [ ] Align default SSO provider model name with upstream `ssoProvider` instead of Ruby's current `ssoProviders`, or provide a migration-compatible alias strategy.
- [ ] Add field-name override support from upstream `fields`.
- [ ] Add upstream-style user reference semantics for `userId`.
- [x] Stop storing `domainVerificationToken` on the provider row for the upstream path; store pending tokens in internal verification storage with expiry.
- [ ] Only include `domainVerified` when domain verification is enabled, matching upstream schema behavior.

## Registration Differences

- [x] Enforce `providersLimit`, including numeric, function, zero/disabled, and maximum-reached behavior.
- [x] Validate issuer as a URL and match upstream error behavior.
- [x] Validate `organizationId` membership before accepting org-linked providers.
- [x] Return upstream duplicate-provider behavior: `UNPROCESSABLE_ENTITY` and message `SSO provider with this providerId already exists`.
- [x] Hydrate OIDC config during registration unless `skipDiscovery` is true.
- [x] Preserve explicit OIDC fields while filling missing fields from discovery.
- [x] Validate SAML metadata size.
- [ ] Validate SAML config algorithms at registration.
- [x] Reject SAML configs without a usable IdP entry point, IdP metadata XML, or IdP singleSignOnService.
- [ ] Set initial `domainVerified` and `domainVerificationToken` response shape according to `domainVerification.enabled`.

## Provider Management Differences

- [ ] Match list/get access rules:
  - [x] User-owned providers without org.
  - [x] Org providers visible to org owners/admins.
  - [x] Comma-separated roles.
  - [x] Non-admin members excluded.
  - [x] User-owned org providers visible when organization plugin is disabled.
- [ ] Match provider sanitization:
  - [x] Never expose `clientSecret`.
  - [x] Mask short and long client IDs as upstream does.
  - [x] Do not expose raw certificate PEM.
  - [x] Return parse errors for invalid certs.
  - [x] Include `spMetadataUrl`.
- [ ] Match update behavior:
  - [x] Reject empty updates.
  - [x] Validate issuer URL.
  - [x] Reject SAML config updates on OIDC-only providers.
  - [x] Reject OIDC config updates on SAML-only providers.
  - [x] Merge partial SAML/OIDC configs instead of replacing blindly.
  - [x] Reset `domainVerified` only when the domain actually changes.
  - [x] Enforce org owner/admin update/delete access.
- [ ] Ensure deleting a provider does not delete linked accounts.

## OIDC Differences

- [ ] Implement full OIDC discovery helper behavior:
  - [ ] `computeDiscoveryUrl`
  - [ ] `validateDiscoveryUrl`
  - [ ] `validateDiscoveryDocument`
  - [ ] `selectTokenEndpointAuthMethod`
  - [ ] `normalizeDiscoveryUrls`
  - [ ] `normalizeUrl`
  - [ ] `needsRuntimeDiscovery`
  - [ ] `fetchDiscoveryDocument`
  - [ ] `discoverOIDCConfig`
  - [ ] `ensureRuntimeDiscovery`
- [x] Preserve issuer path when resolving relative discovery endpoints. Ruby now resolves relative discovery endpoints against the full issuer base path.
- [ ] Match discovery error taxonomy and status mapping, including invalid URL, non-HTTP protocol, untrusted origin, not found, timeout, invalid JSON, incomplete document, issuer mismatch, and unexpected server errors.
- [ ] Perform runtime discovery before authorization URL generation and token exchange when stored config is incomplete. Authorization URL runtime discovery for missing authorization/token endpoints is implemented; callback-time JWKS discovery is implemented for ID-token user info, but upstream's eager JWKS discovery before token exchange still needs deeper parity.
- [x] Generate authorization URLs with PKCE, `login_hint`, per-request scopes, default `offline_access`, and shared/custom redirect URI.
- [x] Implement real authorization-code exchange against `tokenEndpoint`, including `client_secret_basic` and `client_secret_post`.
- [x] Fetch UserInfo when configured, apply mappings, support `extraFields`, and support `sub` mapping when no ID token is returned.
- [x] Validate ID tokens against JWKS when using ID-token user info.
- [x] Reject callbacks missing required user `email` or `id`.
- [ ] Implement `defaultOverrideUserInfo` and trusted/domain-verified provider linking semantics. `defaultOverrideUserInfo`/stored `overrideUserInfo` now updates existing profile fields; trusted/domain-verified account linking semantics still need deeper parity.
- [x] Implement `trustEmailVerified`, `disableImplicitSignUp`, `requestSignUp`, `provisionUser`, and `provisionUserOnEveryLogin`.
- [x] Fix new-user redirect behavior so `newUserCallbackURL` is used only for newly registered users.
- [x] Support `defaultSSO` OIDC providers and sign-in by provider ID, email domain, and explicit domain.
- [x] Support `organizationSlug` lookup during sign-in.

## SAML Differences

- [x] Make real XML SAML processing the default behavior, using `ruby-saml` or an equivalent parser/validator, not the current JSON fallback.
- [x] Generate real SAML AuthnRequests by default. The current fallback base64-encodes JSON as `SAMLRequest`.
- [x] Support signed AuthnRequests, including RelayState in the signed URL.
- [x] Reject `authnRequestsSigned` configs without a private key.
- [ ] Support IdP metadata fallback behavior: metadata XML, `entityID`, `singleSignOnService`, and top-level config fallback.
- [ ] Support `defaultSSO` SAML providers in sign-in, callback, and provider lookup.
- [x] Validate SAML response size before parsing.
- [ ] Strip whitespace from base64 SAMLResponse before decoding.
- [ ] Validate exactly one Assertion or EncryptedAssertion using structured XML parsing rather than regex only.
- [ ] Reject XSW patterns, nested injected assertions, invalid base64, non-XML, and parser errors.
- [ ] Validate algorithms against plugin-level policy for response and config.
- [x] Validate assertion timestamps with default clock skew and `requireTimestamps`.
- [x] Implement `allowIdpInitiated` and default InResponseTo validation behavior.
- [x] Implement verification-table/AuthnRequest storage with TTL and provider mismatch protection.
- [ ] Implement safe redirect URL behavior: allow relative same-origin paths, block protocol-relative URLs, block callback-route loops, prefer RelayState callbackURL, fallback to provider callbackUrl/app base URL. SLO LogoutResponse now blocks malicious RelayState and callback loops; ACS safe redirect parity still needs expansion.
- [ ] Align ACS error redirects and error codes with upstream behavior.
- [ ] Implement account linking/trusted provider semantics via `handleOAuthUserInfo` equivalent behavior.
- [x] Default SAML `emailVerified` to false unless trusted, matching upstream.
- [x] Support SAML mapping fields: `id`, `email`, `emailVerified`, `name`, `firstName`, `lastName`, `extraFields`.
- [x] Implement SAML `disableImplicitSignUp`, `provisionUser`, and `provisionUserOnEveryLogin`.
- [x] Store SAML session records for SLO when enabled.
- [x] Store upstream-style SLO session lookup keys, use NameID/SessionIndex for SP-initiated logout, and delete local session/cookie on initiation.

## Domain Verification and Organization Linking Differences

- [x] Implement upstream domain verification access control: session required, provider owner required, and org membership required for org-linked providers.
- [x] Store pending verification tokens in verification storage with 1-week expiry.
- [x] Reuse active pending tokens on repeated request.
- [x] Return `201 { domainVerificationToken }` from request.
- [x] Return `204` with no body on successful verification.
- [x] Return upstream conflict/not-found/bad-gateway errors for already verified, no pending token, DNS mismatch, invalid domain, and DNS label limit.
- [x] Generate verification identifiers as `_{tokenPrefix || "better-auth-token"}-{providerId}`.
- [x] Extract hostnames from bare domains and full URLs.
- [x] Resolve DNS TXT records and match `identifier=value`.
- [x] Support custom token prefix.
- [ ] Support secondary storage path if the Ruby core has equivalent secondary storage.
- [x] Implement organization assignment from provider during SSO login without requiring email-domain match.
- [ ] Implement organization assignment by verified email domain after generic OAuth callbacks when the organization plugin is present.
- [x] Support `organizationProvisioning.disabled`, `defaultRole`, and `getRole`.
- [ ] Avoid duplicate memberships and prefer verified provider when multiple providers claim the same domain.

## Utility Differences

- [x] Add dedicated Ruby equivalents/tests for `validateEmailDomain`:
  - [x] exact domain match
  - [x] subdomain match
  - [x] suffix trap rejection
  - [x] comma-separated domains
  - [x] whitespace and empty segments
  - [x] case insensitivity
  - [x] empty email/domain and missing `@`
- [x] Add dedicated Ruby equivalents/tests for `getHostnameFromDomain`:
  - [x] bare domain
  - [x] full URL
  - [x] URL with port
  - [x] subdomain
  - [x] URL with path
  - [x] empty input

## Test Parity Checklist

- [ ] Port `upstream/packages/sso/src/oidc/discovery.test.ts` themes.
- [ ] Port `upstream/packages/sso/src/oidc.test.ts` themes.
- [ ] Port `upstream/packages/sso/src/providers.test.ts` themes.
- [ ] Port `upstream/packages/sso/src/domain-verification.test.ts` themes.
- [ ] Port `upstream/packages/sso/src/utils.test.ts` themes.
- [ ] Port `upstream/packages/sso/src/linking/org-assignment.test.ts` themes.
- [ ] Port `upstream/packages/sso/src/saml/algorithms.test.ts` themes.
- [ ] Port `upstream/packages/sso/src/saml/assertions.test.ts` themes.
- [ ] Port `upstream/packages/sso/src/saml.test.ts` integration themes.
- [ ] Add a Ruby-relevant equivalent for `upstream/e2e/smoke/test/saml.spec.ts` defaultSSO smoke coverage.

## Current Ruby Tests That Need Rework

- [ ] Rewrite `test_saml_metadata_authn_request_and_acs_flow` so it no longer accepts base64 JSON as a valid default SAML response.
- [ ] Keep optional adapter tests for `BetterAuth::SSO::SAML.sso_options`, but make the core plugin path secure by default.
- [ ] Expand OIDC tests beyond injected callbacks to cover real token/userinfo/id-token paths.
- [ ] Expand provider CRUD tests to upstream endpoint names and access-control matrix.
- [ ] Expand domain verification tests to real DNS/TXT behavior through injectable resolver or local test adapter.

## Suggested Implementation Order

- [ ] Phase 1: Add upstream-compatible routes, schema gates, and provider CRUD/access semantics.
- [ ] Phase 2: Implement OIDC discovery, auth URL, callback/token processing, and OIDC test parity.
- [ ] Phase 3: Replace default SAML path with XML validation, AuthnRequest generation, InResponseTo, replay, timestamp, and redirect parity.
- [ ] Phase 4: Implement domain verification storage/DNS behavior and org assignment/linking.
- [ ] Phase 5: Implement SAML SLO.
- [ ] Phase 6: Fill remaining utility, smoke, and edge-case tests.
