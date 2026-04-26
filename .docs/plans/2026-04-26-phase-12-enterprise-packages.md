# Phase 12 Enterprise Packages Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` when the work can be split into independent tasks, or `executing-plans` when implementing sequentially in one session. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the server-relevant parts of upstream `sso`, `scim`, `stripe`, and `expo` packages into the Ruby core gem as Better Auth plugins.

**Architecture:** Phase 12 plugins live inside `packages/better_auth` as `BetterAuth::Plugins.sso`, `scim`, `stripe`, and `expo`, matching the existing Ruby plugin packaging used for passkey and OAuth proxy. Runtime dependencies stay minimal: integrations that normally require external services use injected callables or fake clients in tests. Organization, OIDC provider, and OAuth provider integrations remain guarded until those earlier phases are ported.

**Tech Stack:** Ruby 3.2+, Rack 3, Minitest, StandardRB, JSON/JWT/BCrypt from the core gem, stdlib URI/Net::HTTP/OpenSSL, and upstream Better Auth packages as the source of truth.

---

## Task 1: Package Boundary And Loader

**Files:**
- Modify: `packages/better_auth/lib/better_auth.rb`
- Create: `packages/better_auth/lib/better_auth/plugins/sso.rb`
- Create: `packages/better_auth/lib/better_auth/plugins/scim.rb`
- Create: `packages/better_auth/lib/better_auth/plugins/stripe.rb`
- Create: `packages/better_auth/lib/better_auth/plugins/expo.rb`
- Test: `packages/better_auth/test/better_auth/plugins/sso_test.rb`
- Test: `packages/better_auth/test/better_auth/plugins/scim_test.rb`
- Test: `packages/better_auth/test/better_auth/plugins/stripe_test.rb`
- Test: `packages/better_auth/test/better_auth/plugins/expo_test.rb`

- [x] Write failing tests proving each new public plugin constructor exists and registers endpoints/schema.
- [x] Run each new plugin test file and verify failures are caused by missing plugin methods.
- [x] Create the four plugin files with minimal `Plugin.new(...)` constructors.
- [x] Require the plugin files from `packages/better_auth/lib/better_auth.rb`.
- [x] Run the four test files and verify the constructor/registration tests pass.

## Task 2: SSO Plugin

**Upstream source and tests:**
- Source: `upstream/packages/sso/src/index.ts`, `routes/sso.ts`, `routes/providers.ts`, `routes/domain-verification.ts`, `oidc/*`, `saml/*`, `linking/org-assignment.ts`.
- Tests: `domain-verification.test.ts`, `providers.test.ts`, `oidc.test.ts`, `oidc/discovery.test.ts`, `saml.test.ts`, `saml/algorithms.test.ts`, `saml/assertions.test.ts`, `utils.test.ts`, `linking/org-assignment.test.ts`.

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/sso.rb`
- Test: `packages/better_auth/test/better_auth/plugins/sso_test.rb`
- Test: `packages/better_auth/test/better_auth/plugins/sso_saml_test.rb`
- Test: `packages/better_auth/test/better_auth/plugins/sso_oidc_test.rb`

- [x] Add tests for `ssoProvider` schema fields and provider CRUD under `/sso/providers`.
- [x] Add tests for `/sso/register`, `/sign-in/sso`, `/sso/callback/:providerId`, `/sso/saml2/callback/:providerId`, `/sso/saml2/sp/acs/:providerId`, and `/sso/saml2/sp/metadata`.
- [x] Add focused tests for OIDC discovery validation, domain validation, RelayState open-redirect protection, SAML replay protection, and SAML origin-check skip paths.
- [x] Implement provider persistence, sanitized responses, domain verification token lifecycle, SSO redirects, OIDC callback user/session creation, and SAML callback/ACS handling.
- [x] Implement and document verified-domain organization membership assignment when the organization plugin is enabled.

## Task 3: SCIM Plugin

**Upstream source and tests:**
- Source: `upstream/packages/scim/src/index.ts`, `routes.ts`, `middlewares.ts`, `scim-filters.ts`, `patch-operations.ts`, `mappings.ts`, `scim-resources.ts`, `scim-metadata.ts`, `scim-tokens.ts`, `user-schemas.ts`.
- Tests: `upstream/packages/scim/src/scim.test.ts`.

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/scim.rb`
- Test: `packages/better_auth/test/better_auth/plugins/scim_test.rb`

- [x] Add tests for `scimProvider` schema, `/scim/generate-token`, plain/hashed/custom token storage, and Bearer auth middleware.
- [x] Add tests for SCIM metadata endpoints: `/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas`, `/scim/v2/Schemas/:schemaId`, `/scim/v2/ResourceTypes`, `/scim/v2/ResourceTypes/:resourceTypeId`.
- [x] Add tests for `/scim/v2/Users` POST/GET and `/scim/v2/Users/:userId` GET/PUT/PATCH/DELETE with SCIM response shapes and errors.
- [x] Implement token validation, SCIM user/account mapping, filter parsing for common `userName` and `externalId` filters, PATCH `replace/add/remove`, and SCIM error JSON.
- [x] Expand SCIM PATCH coverage for slash-prefixed paths, `remove`, no-path value objects, and invalid filter errors.

## Task 4: Stripe Plugin

**Upstream source and tests:**
- Source: `upstream/packages/stripe/src/index.ts`, `routes.ts`, `schema.ts`, `hooks.ts`, `middleware.ts`, `metadata.ts`, `utils.ts`, `error-codes.ts`.
- Tests: `upstream/packages/stripe/test/stripe.test.ts`, `upstream/packages/stripe/test/stripe-organization.test.ts`.

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/stripe.rb`
- Test: `packages/better_auth/test/better_auth/plugins/stripe_test.rb`
- Test: `packages/better_auth/test/better_auth/plugins/stripe_organization_test.rb`

- [x] Add tests for schema merge: `subscription`, `user.stripeCustomerId`, and guarded `organization.stripeCustomerId`.
- [x] Add tests using an injected fake Stripe client for customer sync, checkout upgrade, billing portal, list subscriptions, cancel, restore, subscription success, and webhook signature handling.
- [x] Implement `/subscription/upgrade`, `/subscription/cancel`, `/subscription/cancel/callback`, `/subscription/restore`, `/subscription/list`, `/subscription/success`, `/subscription/billing-portal`, and `/stripe/webhook`.
- [x] Implement metadata helper protection and reference authorization so user/org subscriptions cannot cross reference boundaries.
- [x] Persist missing subscriptions from Stripe subscription webhook metadata when a created/updated event arrives before a local record exists.
- [x] Document organization integration as guarded until the organization plugin exists.

## Task 5: Expo Plugin

**Upstream source and tests:**
- Source: `upstream/packages/expo/src/index.ts`, `routes.ts`.
- Tests: server-relevant cases from `upstream/packages/expo/test/expo.test.ts`; client storage/focus/online tests are out of Ruby server scope.

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/expo.rb`
- Test: `packages/better_auth/test/better_auth/plugins/expo_test.rb`

- [x] Add tests for `/expo-authorization-proxy`, signed state cookie, optional `oauthState` cookie, and redirect behavior.
- [x] Add tests for `expo-origin` overriding missing `Origin`, `disable_origin_override`, trusted development `exp://`, and deep-link cookie injection for trusted non-HTTP redirects.
- [x] Implement endpoint, request hook, after hook, and feature notes for server-only Expo parity.

## Task 6: Documentation And Verification

**Files:**
- Create: `.docs/features/sso.md`
- Create: `.docs/features/scim.md`
- Create: `.docs/features/stripe.md`
- Create: `.docs/features/expo.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `.docs/plans/2026-04-25-better-auth-ruby-port.md`
- Modify: `.docs/plans/2026-04-26-phase-12-enterprise-packages.md`

- [x] Add feature docs with upstream references, implemented routes, Ruby adaptations, deferred boundaries, and test commands.
- [x] Update parity matrix rows from `Not started` to `Partial` or `Ported` according to passing tests.
- [x] Update the master port plan Phase 12 checkboxes for completed work.
- [x] Run:
  - `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_test.rb`
  - `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_oidc_test.rb`
  - `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_saml_test.rb`
  - `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/scim_test.rb`
  - `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_test.rb`
  - `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_organization_test.rb`
  - `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/expo_test.rb`
  - `cd packages/better_auth && rbenv exec bundle exec rake test`
  - `cd packages/better_auth && rbenv exec bundle exec standardrb`
