# Phase 11/12 Parity Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` when splitting tracks across workers, or `executing-plans` when implementing sequentially. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the real remaining Phase 11 and Phase 12 parity gaps without marking partial protocol/security behavior as complete.

**Architecture:** Keep all protocol and enterprise behavior framework-agnostic in `packages/better_auth`. Prefer maintained external dependencies for security-sensitive protocol code, especially SAML XML signature/encryption validation and Stripe SDK compatibility, while keeping plugin public APIs stable.

**Tech Stack:** Ruby 3.2+, Rack 3, Minitest, StandardRB, `jwt`, existing `BetterAuth::Crypto`, upstream Better Auth v1.4.22 tests, proposed `ruby-saml >= 1.18.1`, proposed optional `stripe` gem compatibility tests.

---

## Current State And Upstream Findings

- [x] Phase 11 currently covers core OIDC/OAuth/MCP/device-auth flows: metadata, registration, authorize, consent, token, refresh, userinfo, introspection, revoke, device polling, and MCP metadata/helpers.
- [x] Phase 12 currently covers useful server behavior for SSO, SCIM, Stripe, and Expo, but several areas are intentionally partial.
- [x] Upstream SSO uses external SAML/XML/JWT dependencies: `samlify`, `fast-xml-parser`, and `jose`.
- [x] Upstream Stripe uses the official `stripe` package as a peer dependency and has a broad edge-case suite: about 90 Stripe tests across `stripe.test.ts` and `stripe-organization.test.ts`.
- [x] Upstream SCIM has one large test file with about 53 cases and implements its own SCIM filter/PATCH behavior.
- [x] Upstream Phase 11 protocol coverage is broad: about 172 tests across OAuth provider, OIDC provider, MCP, and device authorization.
- [x] Upstream SAML coverage is broad: about 139 SAML-specific tests covering algorithms, assertions, timestamps, replay, ACS, IdP-initiated flows, and security cases.
- [x] `ruby-saml` is the preferred Ruby SAML dependency candidate. RubyGems lists `ruby-saml 1.18.1` released July 29, 2025, MIT licensed, with `nokogiri` and `rexml` runtime dependencies. RubySec advisories for parser/signature bypasses are patched in `>= 1.18.0`.
- [x] The official `stripe` gem is the preferred SDK compatibility target. RubyGems lists `stripe 19.1.0` released April 24, 2026 by Stripe.

Primary references:

- Upstream SSO: `upstream/packages/sso/src/`
- Upstream SCIM: `upstream/packages/scim/src/scim.test.ts`
- Upstream Stripe: `upstream/packages/stripe/test/stripe.test.ts`, `upstream/packages/stripe/test/stripe-organization.test.ts`
- Upstream OAuth provider: `upstream/packages/oauth-provider/src/**/*.test.ts`
- Upstream OIDC/MCP/device auth: `upstream/packages/better-auth/src/plugins/oidc-provider/`, `mcp/`, `device-authorization/`
- Dependency/security notes: RubyGems `ruby-saml`, SAML-Toolkits `ruby-saml`, RubySec CVE-2025-25292, CVE-2025-66567, CVE-2025-66568, RubyGems `stripe`

## Task 1: Dependency And Boundary Decisions

**Files:**

- Modify: `packages/better_auth/better_auth.gemspec`
- Modify: `packages/better_auth/Gemfile`
- Modify: `packages/better_auth/lib/better_auth/plugins/sso.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/stripe.rb`
- Modify: `.docs/features/sso.md`
- Modify: `.docs/features/stripe.md`

- [ ] Add `ruby-saml >= 1.18.1` and its lockfile updates for SAML security parity.
- [ ] Keep SAML dependency usage isolated behind a small internal SSO adapter so existing SSO route code does not depend directly on gem-specific classes everywhere.
- [ ] Keep the Stripe plugin public API as `stripe_client:` injection-first. Add official `stripe` gem compatibility as test/dev support and document app-level installation for production Stripe usage.
- [ ] Document that `ruby-saml` is chosen over native XML signature/encryption code because hand-rolled SAML XML security is higher risk.
- [ ] Run dependency audit commands available in the repo after lockfile changes, and record any advisory decisions in `.docs/features/sso.md`.

Verification:

```bash
cd packages/better_auth
rbenv exec bundle install
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/sso_saml_test.rb
rbenv exec bundle exec standardrb
```

## Task 2: SAML Security Parity

**Files:**

- Create or modify: `packages/better_auth/lib/better_auth/plugins/sso/saml_adapter.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/sso.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/sso_saml_test.rb`
- Create fixtures as needed under `packages/better_auth/test/fixtures/saml/`
- Modify: `.docs/features/sso.md`
- Modify: `.docs/features/upstream-parity-matrix.md`

- [ ] Port upstream single-assertion enforcement from `saml/assertions.test.ts`: no assertion, multiple assertions, mixed plain/encrypted assertions, wrapped assertions, nested injected assertions, and namespace-prefix variants.
- [ ] Port upstream algorithm validation from `saml/algorithms.test.ts`: secure signature/digest/encryption algorithms, deprecated algorithm warning/reject/allow behavior, custom allow-lists, short-form algorithm names, unknown algorithm rejection, and encrypted assertion algorithm extraction.
- [ ] Replace the simplified SAML JSON/base64 path with real XML SAML response processing through `ruby-saml`.
- [ ] Preserve existing `validate_response` hook, but execute it only after XML signature/assertion validation succeeds.
- [ ] Implement SAML timestamp validation equivalent to upstream: missing conditions behavior, invalid timestamps, future `NotBefore`, expired `NotOnOrAfter`, accepted clock skew, and configurable missing-condition policy.
- [ ] Preserve replay protection using assertion IDs and the existing verification storage pattern.
- [ ] Add signed AuthnRequest coverage and SP metadata coverage using configured certificate/private key.
- [ ] Add encrypted assertion coverage if `ruby-saml` supports the needed decryption path with configured SP private key.
- [ ] Add IdP metadata parsing/fallback tests, ACS origin bypass tests, IdP-initiated flow tests, RelayState open-redirect tests, and SAML response size-limit tests.
- [ ] Document any `ruby-saml` limitation versus upstream `samlify`, especially separate signing/encryption cert support if not available.

Verification:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/sso_saml_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/sso_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/sso_oidc_test.rb
```

## Task 3: SCIM RFC And Provider Parity

**Files:**

- Modify: `packages/better_auth/lib/better_auth/plugins/scim.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/scim_test.rb`
- Modify: `.docs/features/scim.md`
- Modify: `.docs/features/upstream-parity-matrix.md`

- [ ] Port remaining upstream token tests: require user session, invalid provider rejection, organization token generation, token hooks before/after generation, encrypted token storage, and custom encrypted token storage.
- [ ] Expand SCIM metadata tests: unsupported schema/resource type 404s and exact response shapes for ServiceProviderConfig, Schemas, ResourceTypes, and User schema.
- [ ] Expand create-user behavior: link account to existing user, external id mapping, name parts, formatted name, primary email selection, first non-primary email selection, duplicate computed username rejection, and invalid anonymous access.
- [ ] Expand update behavior: invalid updates, missing resources, anonymous access, and provider/org isolation.
- [ ] Expand PATCH behavior: mixed operations, dot notation paths, add idempotency, ignored non-existing operations, invalid update handling, no-path values, remove operations, and missing-user behavior.
- [ ] Expand list/get/delete behavior: provider isolation, organization isolation, filtering, missing resources, invalid tokens, and default SCIM provider behavior.
- [ ] Keep SCIM parsing dependency-free unless upstream parity forces a parser dependency; current upstream SCIM package does not depend on a SCIM parser library.

Verification:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/scim_test.rb
```

## Task 4: Stripe Billing Edge-Case Parity

**Files:**

- Modify: `packages/better_auth/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/stripe_test.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/stripe_organization_test.rb`
- Modify: `.docs/features/stripe.md`
- Modify: `.docs/features/upstream-parity-matrix.md`

- [ ] Port metadata helper protections: internal field protection and typed extraction for customer/subscription metadata.
- [ ] Port subscription creation and upgrade matrix: duplicate subscription prevention, same-plan same-seat rejection, same-plan seat upgrades, monthly-to-annual upgrades, upgrade existing active subscription when canceled subscriptions exist, and user/org subscription separation.
- [ ] Port trial-abuse matrix: prevent multiple free trials for the same user, prevent past-trial abuse on incomplete subscriptions, and prevent free trials across different plans.
- [ ] Port webhook matrix: subscription created/updated/deleted, trial fields, missing user, missing plan, duplicate existing subscription, metadata subscriptionId skip, event handler callbacks, updated subscription callback return value, invalid signature, missing signature, async signature verification, constructEventAsync nil, async processing errors, and Stripe v18/v19/v20 compatibility shape where applicable to Ruby SDK.
- [ ] Port cancellation and restore sync fields: `cancelAtPeriodEnd`, `cancelAt`, `canceledAt`, `endedAt`, immediate cancellation, scheduled cancellation, period-end cancellation, and restore clearing cancellation fields.
- [ ] Port customer sync matrix: reuse existing Stripe customers, avoid duplicate customer creation on signup plus upgrade, distinguish user and organization customers with same email, sync user email/name updates, and merge `getCustomerCreateParams` nested values.
- [ ] Port organization matrix: customer creation, existing customer reuse, billing portal, cancel/restore/list, dashboard-created webhook subscriptions, cross-organization blocking, missing `authorizeReference`, organization not found, Stripe customer creation failure, callback errors, organization hooks, and deletion blocking when active subscriptions exist.
- [ ] Add official `stripe` gem compatibility tests for object/hash response access without making live network calls.
- [ ] Do not call Stripe network APIs in tests; continue using fake/injected clients.

Verification:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/stripe_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/stripe_organization_test.rb
```

## Task 5: OAuth/OIDC/MCP Protocol Matrix Parity

**Files:**

- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_provider.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/oidc_provider_test.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/oauth_provider_test.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/mcp_test.rb`
- Modify: `.docs/features/oidc-provider.md`
- Modify: `.docs/features/oauth-provider.md`
- Modify: `.docs/features/mcp.md`
- Modify: `.docs/features/upstream-parity-matrix.md`

- [ ] Port OAuth provider logout tests from `upstream/packages/oauth-provider/src/logout.test.ts`, including config variants and JWT-plugin-disabled behavior where applicable.
- [ ] Port organization client registration/reference tests from `register.test.ts` and related OAuth provider tests now that Phase 10 exists.
- [ ] Port token client-secret validation matrix from `token.test.ts`: public clients, confidential clients, `client_secret_basic`, `client_secret_post`, missing/invalid secrets, refresh-token variants, and client credentials variants.
- [ ] Add encrypted client-secret storage using existing `BetterAuth::Crypto` helpers and document the storage format.
- [ ] Expand protocol rate-limit tests from upstream OAuth config/rate limiting sections.
- [ ] Expand OIDC JWT behavior: algorithm negotiation, supported alg metadata, ID token signing variants available through current Ruby dependencies, and clear docs for unsupported algorithms.
- [ ] Expand metadata/resource metadata tests for OAuth provider and MCP.
- [ ] Port MCP server-client flow tests from upstream `mcp.test.ts`, including public PKCE registration, authorization, token, refresh, userinfo, protected resource challenge, and resource metadata.
- [ ] Keep protocol code in `packages/better_auth`; do not introduce Rails dependencies.

Verification:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/oidc_provider_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/oauth_provider_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/mcp_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/device_authorization_test.rb
```

## Task 6: Documentation, Matrix, And Completion Criteria

**Files:**

- Modify: `.docs/features/sso.md`
- Modify: `.docs/features/scim.md`
- Modify: `.docs/features/stripe.md`
- Modify: `.docs/features/oidc-provider.md`
- Modify: `.docs/features/oauth-provider.md`
- Modify: `.docs/features/mcp.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `.docs/plans/2026-04-25-better-auth-ruby-port.md`
- Modify: `.docs/plans/2026-04-26-phase-11-protocol-plugins.md`
- Modify: `.docs/plans/2026-04-26-phase-12-enterprise-packages.md`

- [ ] Update feature docs with implemented upstream references, Ruby dependency decisions, exact unsupported differences, and verification commands.
- [ ] Update parity matrix statuses from `Partial` to `Ported` only when the corresponding upstream test families are represented by passing Ruby tests.
- [ ] In the master plan, mark Phase 11/12 future-polish lines complete only after all track verification passes.
- [ ] Preserve any remaining unsupported behavior as explicit documentation rather than a vague “future polish” note.
- [ ] Run full core validation after all tracks pass.

Final verification:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test
rbenv exec bundle exec standardrb
```

## Implementation Notes

- Do not mark a track complete solely because a dependency exists. Mark it complete only after upstream-equivalent tests pass.
- Avoid live network calls in tests. Use fixtures, fake clients, and injected dependencies.
- Prefer upstream public route paths, JSON keys, error strings, and option names. Ruby internals may use snake_case.
- Any new runtime dependency must be documented with version bounds, reason for inclusion, and known security advisory constraints.
- `ruby-saml` must be pinned to a patched range (`>= 1.18.1` recommended at plan time) because older ranges have known SAML authentication bypass advisories.
- Stripe edge-case parity should follow upstream tests, not an invented infinite billing matrix.
