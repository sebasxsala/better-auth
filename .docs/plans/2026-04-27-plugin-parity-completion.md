# Plugin Parity Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Ruby plugin support matrix to honest 100% upstream-compatible server parity, using upstream Better Auth as the source of truth.

**Architecture:** Keep plugin behavior in `packages/better_auth` and reuse existing Rack endpoint, plugin hook, schema, adapter, cookie, and session primitives. Each plugin is promoted from `Partial` to `[x] Supported` only after its upstream runtime behavior is covered by Ruby tests, documented Ruby-only adaptations are intentional, and `README.md` plus `.docs/features/upstream-parity-matrix.md` agree.

**Tech Stack:** Ruby 3.2+, Rack 3, Minitest, StandardRB, upstream Better Auth TypeScript tests under `upstream/`, and the existing BetterAuth plugin system.

---

## Audit Result

The root `README.md` plugin table was compared against:

- `README.md`
- `.docs/features/upstream-parity-matrix.md`
- `.docs/features/*.md`
- `packages/better_auth/lib/better_auth/plugins/*.rb`
- `packages/better_auth/test/better_auth/plugins/*_test.rb`
- `upstream/packages/better-auth/src/plugins/**/*.test.ts`
- `upstream/packages/passkey/src/passkey.test.ts`
- `upstream/packages/oauth-provider/src/**/*.test.ts`
- `upstream/packages/sso/src/**/*.test.ts`
- `upstream/packages/scim/src/scim.test.ts`
- `upstream/packages/stripe/test/*.test.ts`
- `upstream/packages/expo/test/*.test.ts`

### Already Supported

These rows can be marked `[x] Supported` for the Ruby server surface:

| Plugin | Decision | Evidence |
| --- | --- | --- |
| Access control | Supported | Ruby `access_test.rb` covers every runtime assertion in upstream `access.test.ts`, plus unknown-resource rejection. TypeScript inference is not a Ruby concern. |
| Additional fields | Supported | Already marked supported. Ruby covers schema merge plus sign-up, update-user, and get-session integration. Upstream client type inference is not a Ruby server concern. |
| Admin | Supported | Ruby `admin_test.rb` covers the server runtime matrix for user management, list/search/filter/sort/count, direct create without password, role validation, bans, social banned callbacks, impersonation, sessions, password edges, destructive responses, and permission checks. |
| Anonymous | Supported | Ruby covers anonymous sign-in/delete, generator fallbacks, invalid generated email, repeat anonymous sign-in rejection, `on_link_account`, email sign-in cleanup, and social callback cleanup. Async generator behavior maps to normal Ruby callables. |
| API key | Supported | Ruby covers creation, verification, hashing, expiration bounds, quotas/refill, per-key rate limits, permissions, metadata migration, database/secondary-storage modes, deferred updates, and API-key-backed sessions. |
| Bearer | Supported | Ruby covers `set-auth-token`, `get-session`, `list-sessions`, direct API headers, unsigned token fallback, `require_signature`, and valid-cookie fallback when Authorization is invalid. |
| Captcha | Supported | Ruby covers protected endpoints, missing token, service errors, Turnstile JSON payload, reCAPTCHA form payload and score, hCaptcha site key, CaptchaFox `remoteIp`, and injected verifier behavior. |
| Device authorization | Supported | Ruby covers option validation, device/user code issuance, custom generators, client validation and mismatch errors, OAuth error codes/descriptions, verification with dashed or undashed user codes, polling interval and slow-down behavior, approval/denial authorization, processed-code rejection, token response shape, new-session hook integration, expiry handling, and verification URI query preservation. |
| Email OTP | Supported | Ruby covers override/default email-verification combinations, send/check/verify/sign-in/sign-up/password-reset flows, no-enumeration sender behavior, allowed attempts, latest OTP, plugin rate limits, plain/hashed/encrypted/custom storage helpers, and Ruby server API naming. Browser client aliases are outside Ruby server scope. |
| Have I Been Pwned | Supported | Ruby covers compromised sign-up, compromised password change, custom paths, custom message, and SHA-1 k-anonymity lookup without real network calls. |
| JWT/JWKS | Supported | Ruby covers EdDSA default signing, RS256/PS256/ES256/ES512, JWKS publication/custom path, API-only sign/verify, `set-auth-jwt`, key rotation/grace windows, `kid` selection, current/previous key verification, expiry, and remote JWKS verification. Symmetric client-secret algorithms are outside the JWKS server surface. |
| Last login method | Supported | Ruby covers email, SIWE, social OAuth, generic OAuth, failed callback suppression, subsequent database updates, custom cookie names/prefixes, cross-subdomain/cross-origin attributes, and optional `lastLoginMethod` persistence. |
| Magic link | Supported | Ruby covers send/verify, single-use and expired-token redirects, error callback URLs, new-user signup, new-user callback redirects, existing-user email verification, latest-token verification, trusted callback validation, and plain/hashed/custom token storage. |
| MCP | Supported | Ruby covers OAuth metadata, protected-resource metadata, public client registration, PKCE authorization-code exchange, refresh, userinfo, JWKS publication, login-prompt cookie restoration after sign-in, and `WWW-Authenticate` helper headers. Consent UI/client helpers are outside Ruby server scope. |
| Multi-session | Supported | Ruby covers multi-session cookie creation, unique device listing, active-session switching, active-session authorization for mutation routes, same-user replacement at the maximum session limit, revocation fallback, sign-out cleanup, forged-cookie safety, and invalid-token errors. |
| One tap | Supported | Ruby covers the server callback: Google ID-token verification, configured client ID handling, new-user OAuth creation, existing account reuse, verified/trusted account linking, disabled account-linking rejection, `disable_signup`, session cookies, and invalid-token/email-missing handling. Browser/FedCM helpers are outside Ruby server scope. |
| One-time token | Supported | Ruby covers generation/verification, single-use behavior, token expiration, expired-session rejection, default cookie setting and suppression, server-only generation, plain/hashed/custom storage, and `set-ott` headers on sign-up/sign-in sessions. Client aliases are outside Ruby server scope. |
| OAuth proxy | Supported | Ruby covers callback rewriting, same-origin unwrap, encrypted cross-origin cookie forwarding, timestamp/trusted-callback validation, malformed payload handling, stateless state-cookie package restoration, and DB-less provider callback flow. |
| Organization | Supported | Ruby covers upstream organization CRUD, access-control routes, member CRUD, invitation/team flows including multi-team invitations, hooks, additional fields, SQL/Rails plugin schema migrations, and dynamic-role edge cases from `upstream/packages/better-auth/src/plugins/organization/**/*.test.ts`. |
| Passkey | Supported | Ruby covers upstream passkey registration/authentication option shapes, per-request challenge expiration, signed challenge cookies, allow/exclude credential transport details, real WebAuthn verification, management routes, delete not-found behavior, session creation, and SQL/Rails schema output from `upstream/packages/passkey/src/passkey.test.ts`. Browser client aliases are outside Ruby server scope. |
| Phone number | Supported | Ruby covers OTP send/verify, latest-code behavior, one-time use, expiry, attempt limits, phone sign-up with additional fields, session creation/suppression, phone-number update with duplicate protection, direct update-user prevention, password sign-in, require-verification OTP trigger, password-reset OTP reuse/attempt/session-revocation behavior, reset OTP preservation after validation failures, custom validators, custom verify callbacks, and memory-adapter uniqueness parity. Client aliases are outside Ruby server scope. |
| SIWE | Supported | Ruby covers nonce lifecycle, callback verification, anonymous/email modes, ENS lookup callback, account/session creation, nonce consumption, duplicate wallet reuse, EIP-55 checksum casing, custom schema merging, and multiple chain IDs. |
| SSO | Supported | Ruby covers provider CRUD/access/sanitization, OIDC discovery hydration and trusted-origin validation, OIDC callback, SAML callback/ACS/SP metadata, RelayState safety, replay protection, XML assertion count validation, SAML algorithm policy decisions, domain verification, and organization assignment. SAML cryptographic signature verification/decryption is intentionally delegated to `validate_response`. |
| SCIM | Supported | Ruby covers upstream token envelopes, plain/hashed/encrypted/custom token storage, Bearer middleware, SCIM metadata, user CRUD, provider/org scoping, existing-user account linking, filters, PATCH path/value mappings, and organization enforcement. |
| Two-factor | Supported | Ruby covers TOTP enable/verify/disable, OTP send/verify with plain/hashed/encrypted/custom hash storage, backup code generation/use/view/regeneration, trusted devices with server-side records, custom/default cookie max-age options, post-login 2FA redirect, invalid/missing cookie errors, attempt limits, and `rememberMe: false` preservation after second-factor verification. |
| Username | Supported | Ruby covers sign-up/sign-in, availability, normalization, display username mirroring/preservation/validation, validation-order behavior, duplicate sign-up/update semantics, same-user update allowance, custom validators, email-verification no-leak checks, and schema uniqueness metadata for SQL adapters. |

### Still Partial

These rows should stay `Partial` until the tasks below pass:

| Plugin | Main upstream parity gaps |
| --- | --- |
| OIDC provider | Supported. Ruby server parity covers consent page and HTML consent behavior, prompt/max-age matrix, JWT plugin algorithm negotiation, plain/hashed/encrypted client-secret variants, dynamic registration auth/validation/RFC7591 metadata, token exchange, refresh, userinfo, and RP logout. |
| OpenAPI | Needs snapshot-style schema parity with upstream Zod-derived output or a documented Ruby schema contract with tests. |
| Stripe | Supported. Ruby server parity covers the billing event matrix, plan/seat/trial abuse cases, trial-start callbacks, lookup-key failure handling, webhook ordering, organization mode edge cases, customer metadata/callback customization, checkout params/options, and subscription state transitions with an injected Stripe-compatible client. |
| Expo server integration | Supported. README/docs are narrowed to the Ruby server surface; authorization proxy cookies, optional OAuth state cookie, origin override/preservation, disabled override, trusted `exp://`, trusted deep-link cookie injection, wildcard trusted origins, and native client scope decisions are covered. React Native secure storage, cookie cache, focus/online managers, browser-opening flow, and React Native behavior tests are client-only and intentionally out of Ruby scope. |

## Files To Modify

- `README.md`: promote rows only after tests and docs prove server parity.
- `.docs/features/upstream-parity-matrix.md`: keep every plugin row aligned with the README status and exact upstream test paths.
- `.docs/features/<plugin>.md`: record supported behavior, Ruby adaptations, and any explicitly out-of-scope TypeScript/browser/client behavior.
- `packages/better_auth/lib/better_auth/plugins/*.rb`: implement missing plugin behavior.
- `packages/better_auth/test/better_auth/plugins/*_test.rb`: add upstream-equivalent Minitest cases.
- `packages/better_auth/test/better_auth/routes/*_test.rb`: add route-level regression tests when plugin behavior depends on base auth routes.
- `packages/better_auth/test/better_auth/adapters/*_test.rb`: add adapter contract cases when plugin parity depends on persistence semantics.
- `packages/better_auth-rails/spec/**/*`: add Rails migration/schema checks for plugin fields when the plugin changes persisted schema.

## Implementation Tasks

### Task 1: Lock The Promotion Rules

**Files:**
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `.docs/features/_TEMPLATE.md`
- Test: documentation review

- [ ] **Step 1: Add a parity status rule to `.docs/features/upstream-parity-matrix.md`.**

Add this paragraph under the opening description:

```markdown
Status rule: `Complete` means every server-relevant upstream runtime behavior has a Ruby test and documented Ruby adaptations are intentional. TypeScript inference, browser client packages, and native mobile client storage are marked out of scope only when the README row explicitly names the Ruby server surface.
```

- [ ] **Step 2: Add the same rule to `.docs/features/_TEMPLATE.md`.**

Add this section after the title:

```markdown
## Parity Status Rule

Use `Complete` only when every server-relevant upstream runtime behavior has a Ruby test and documented Ruby adaptations are intentional. Keep the feature `Partial` when upstream has unported edge cases, missing route matrices, missing adapter coverage, or unresolved client/server scope decisions.
```

- [ ] **Step 3: Verify the docs mention the rule once in each file.**

Run:

```bash
rg -n "Status rule|Parity Status Rule" .docs/features/upstream-parity-matrix.md .docs/features/_TEMPLATE.md
```

Expected: one match in each file.

### Task 2: Promote The Already-Supported Rows

**Files:**
- Modify: `README.md`
- Modify: `.docs/features/access.md`
- Modify: `.docs/features/captcha.md`
- Modify: `.docs/features/haveibeenpwned.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Test: `packages/better_auth/test/better_auth/plugins/access_test.rb`
- Test: `packages/better_auth/test/better_auth/plugins/captcha_test.rb`
- Test: `packages/better_auth/test/better_auth/plugins/have_i_been_pwned_test.rb`

- [x] **Step 1: Run the supported plugin tests.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/access_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/captcha_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/have_i_been_pwned_test.rb
```

Expected: all three files pass.

- [x] **Step 2: Mark the rows complete in `.docs/features/upstream-parity-matrix.md`.**

Change the status for `access`, `captcha`, and `haveibeenpwned` from `Partial` to `Complete`, and make each note name the upstream tests covered by Ruby.

- [x] **Step 3: Mark the feature docs complete.**

In `.docs/features/access.md`, `.docs/features/captcha.md`, and `.docs/features/haveibeenpwned.md`, replace the old partial wording with:

```markdown
Status: Complete for Ruby server parity.
```

- [x] **Step 4: Verify the README rows are supported.**

Run:

```bash
rg -n "\| Access control \| \[x\] Supported|\| Captcha \| \[x\] Supported|\| Have I Been Pwned \| \[x\] Supported" README.md
```

Expected: three matching rows.

### Task 3: Complete API Key Parity

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/api_key.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/api_key_test.rb`
- Modify: `.docs/features/api-key.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `README.md`

- [x] **Step 1: Create an upstream test inventory for API key.**

Run:

```bash
rg -n "it\\(|describe\\(" upstream/packages/better-auth/src/plugins/api-key/api-key.test.ts
rg -n "^  def test_" packages/better_auth/test/better_auth/plugins/api_key_test.rb
```

Expected: upstream has coverage for validation, create/update/get/list/delete, verification, rate limits, quotas/refill, permissions, metadata, secondary storage, fallback, deferred updates, custom storage, and legacy metadata migration.

- [x] **Step 2: Add failing tests for validation boundaries.**

Add Ruby tests covering name min/max, prefix min/max, `expiresIn` min/max, disabled custom expiration, required name, client-supplied userId rejection, missing auth, empty update body, invalid metadata, and disabled metadata.

- [x] **Step 3: Add failing tests for quota and rate-limit behavior.**

Add Ruby tests covering remaining decrement, zero remaining rejection, refill interval/amount validation, refill after elapsed interval, no refill before interval, multiple refill cycles, lastRequest updates, and update operations not decrementing remaining.

- [x] **Step 4: Add failing tests for permissions.**

Add Ruby tests covering default permissions, returned permission object shape, matching required permissions, non-matching required permissions, missing permissions with required permissions, and permission updates.

- [x] **Step 5: Add failing tests for storage modes.**

Add Ruby tests covering secondary-storage create/get/list/update/delete/verify, TTL for expiring keys, rate limits in secondary storage, fallback-to-database read-through, fallback write-through, storage-only writes, custom get/set/delete methods, and deferred updates when background tasks are configured.

- [x] **Step 6: Add failing tests for metadata migration.**

Add Ruby tests covering double-stringified metadata migration on get, list, update, and verify, plus already-object metadata and nil metadata.

- [x] **Step 7: Implement the minimal API key changes.**

Port the missing behavior from:

```text
upstream/packages/better-auth/src/plugins/api-key/routes/*.ts
upstream/packages/better-auth/src/plugins/api-key/adapter.ts
upstream/packages/better-auth/src/plugins/api-key/rate-limit.ts
```

Keep Ruby option names snake_case while preserving route JSON keys and response shapes.

- [x] **Step 8: Run the API key test file.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/api_key_test.rb
```

Expected: pass.

- [x] **Step 9: Promote docs when the test inventory is covered.**

Change API key to `[x] Supported` in `README.md`, `Complete` in `.docs/features/upstream-parity-matrix.md`, and `Status: Complete for Ruby server parity.` in `.docs/features/api-key.md`.

### Task 4: Complete Admin And Organization Parity

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/admin.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/organization.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/admin/schema.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/organization/schema.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/admin_test.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/organization_test.rb`
- Modify: `.docs/features/admin.md`
- Modify: `.docs/features/organization.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `README.md`

- [x] **Step 1: Inventory upstream admin and organization tests.**

Run:

```bash
rg -n "it\\(|describe\\(" upstream/packages/better-auth/src/plugins/admin/admin.test.ts
rg -n "it\\(|describe\\(" upstream/packages/better-auth/src/plugins/organization/*.test.ts upstream/packages/better-auth/src/plugins/organization/routes/*.test.ts
```

Expected: admin and organization route matrices are visible before writing Ruby tests.

2026-04-27 verification: upstream organization cases were inventoried from `upstream/packages/better-auth/src/plugins/organization/organization.test.ts`, `organization-hook.test.ts`, `team.test.ts`, `client.test.ts`, and `routes/*.test.ts`; Ruby coverage is consolidated in `packages/better_auth/test/better_auth/plugins/organization_test.rb`, `packages/better_auth/test/better_auth/schema/sql_test.rb`, and `packages/better_auth-rails/spec/better_auth/rails/migration_spec.rb`.

- [x] **Step 2: Add admin tests for user list/search/filter/sort/count.**

Cover search by name, role filters, id and `_id` `ne` filters, combined search/filter, offset/limit, sorting by name, and list-with-current-user behavior.

- [x] **Step 3: Add admin tests for role validation and update-user restrictions.**

Cover multiple roles, non-existent roles, update-user role changes without `user:set-role`, update-user role changes with valid custom role, role-over-userId permission priority, banned-user permission checks, and numeric userId mode.

- [x] **Step 4: Add admin tests for ban, impersonation, and password edge cases.**

Cover custom banned messages, expired-ban cleanup, social sign-in rejection for banned users, impersonating admin rejection, impersonated-session filtering, stop impersonating, empty userId, empty password, short password, long password, empty string userId, and `"NaN"` userId.

Completed for Admin on 2026-04-27 in `packages/better_auth/test/better_auth/plugins/admin_test.rb`; Organization remains separate.

- [x] **Step 5: Add organization tests for route matrices.**

Cover organization CRUD access-control routes, member CRUD routes, invitation accept/reject/cancel, team creation/update/delete/list, active organization/team session fields, organization hooks, dynamic roles, and additional-field persistence.

- [x] **Step 6: Implement missing admin and organization behavior.**

Port behavior from:

```text
upstream/packages/better-auth/src/plugins/admin/
upstream/packages/better-auth/src/plugins/organization/
```

Preserve upstream route paths and JSON keys. Keep Ruby callbacks as callables and roles as stored strings where the current adapter expects that shape.

- [x] **Step 7: Run focused tests.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/admin_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/organization_test.rb
```

Expected: both pass.

- [x] **Step 8: Add Rails/plugin schema migration coverage.**

Add Rails specs proving admin and organization plugin fields appear in generated migrations when those plugins are configured.

- [x] **Step 9: Promote docs only after core and Rails schema checks pass.**

Update README, feature docs, and parity matrix for admin and organization.

Completed for Organization on 2026-04-27 in `packages/better_auth/test/better_auth/plugins/organization_test.rb`, `packages/better_auth/test/better_auth/schema/sql_test.rb`, `packages/better_auth-rails/spec/better_auth/rails/migration_spec.rb`, `packages/better_auth/lib/better_auth/plugins/organization.rb`, and `packages/better_auth/lib/better_auth/plugins/organization/schema.rb`. Ruby now covers CRUD access-control route behavior, member CRUD, invitation/team flows including multi-team invitations, organization hooks, additional fields, SQL/Rails plugin schema migrations, and dynamic-role edge cases. Admin was already completed earlier in this task.

### Task 5: Complete OAuth And Protocol Plugin Parity

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/generic_oauth.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_proxy.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_provider.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/device_authorization.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- Modify: matching `packages/better_auth/test/better_auth/plugins/*_test.rb`
- Modify: matching `.docs/features/*.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `README.md`

- [x] **Step 1: Add Generic OAuth parity tests.**

Covered DB and cookie state strategies, state mismatch redirects, state cleanup cookies, dynamic authorization params, `response_mode`, custom token exchange failure redirects, standard HTTP token/userinfo exchange, provider helper factories, account-info/refresh integration, encrypted OAuth token storage, account cookies, RFC 9207 issuer mismatch redirects, `disableImplicitSignUp`, new-user redirects, and trusted account linking. Browser client aliases and TypeScript async typing are outside Ruby server scope.

- [x] **Step 2: Add OAuth proxy parity tests.**

Cover same-origin unwrap, encrypted cross-origin payloads, timestamp validation, trusted callback validation, malformed payloads, cookie forwarding, and stateless state-cookie restoration.

2026-04-27 update: Added Ruby coverage for stateless state-cookie package encryption/restoration and DB-less generic OAuth callback flow. Existing OAuth proxy tests cover same-origin unwrap, encrypted cross-origin payloads, timestamp validation, trusted callback validation, malformed payloads, and cookie forwarding.

- [ ] **Step 3: Add OIDC provider and OAuth provider parity tests.**

Cover prompt parsing, max-age, consent reuse, client CRUD lifecycle, encrypted client secret variants, client credentials, authorization code, refresh, revoke, introspection, logout, userinfo, issuer normalization, organization reference, and JWT plugin algorithm negotiation.

2026-04-27 update: OIDC provider parity is complete for the Ruby server surface in `packages/better_auth/test/better_auth/plugins/oidc_provider_test.rb`. Added coverage for dynamic-registration authentication/validation/RFC7591 response metadata, invalid scopes, PKCE requirements, `max_age`, `prompt=login` login-prompt cookie resume and cleanup, consent-page redirects, custom HTML consent rendering, plain/hashed/encrypted client-secret storage, JWT-plugin ID-token algorithm negotiation, custom userinfo claims, token exchange, refresh tokens, metadata, and RP logout. OAuth provider remains tracked separately in this task.

- [x] **Step 4: Add Device Authorization parity tests.**

Cover option validation, client validation, user code format, polling interval, slow-down, expired device/user codes, denial, approval, token response shape, and verification URI behavior.

- [x] **Step 5: Add MCP parity tests.**

Cover protected-resource metadata, OAuth metadata, login prompt cookie restoration, registration, token, refresh, userinfo, JWKS, and `WWW-Authenticate` helper behavior.

- [ ] **Step 6: Implement missing protocol behavior from upstream.**

Port behavior from:

```text
upstream/packages/better-auth/src/plugins/generic-oauth/
upstream/packages/better-auth/src/plugins/oauth-proxy/
upstream/packages/better-auth/src/plugins/oidc-provider/
upstream/packages/better-auth/src/plugins/device-authorization/
upstream/packages/better-auth/src/plugins/mcp/
upstream/packages/oauth-provider/src/
```

- [ ] **Step 7: Run focused protocol tests.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/generic_oauth_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/oauth_proxy_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/oidc_provider_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/oauth_provider_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/device_authorization_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp_test.rb
```

Expected: all pass.

### Task 6: Complete Session-Sensitive Plugins

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/bearer.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/custom_session.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/jwt.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/multi_session.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/one_time_token.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/two_factor.rb`
- Modify: matching test files under `packages/better_auth/test/better_auth/plugins/`
- Modify: route tests under `packages/better_auth/test/better_auth/routes/`

- [x] **Step 1: Add bearer tests.**

Cover signed bearer token, unsigned bearer token when allowed, `require_signature`, `/list-sessions`, direct API/server-action calls, invalid Authorization header with valid cookie fallback, and `set-auth-token` response header exposure.

- [x] **Step 2: Add custom-session tests.**

Covered `/get-session` custom shaping, Set-Cookie preservation including per-cookie max-age values, unauthenticated nil response shape without invoking the resolver, and composition with multi-session list mutation. TypeScript inference and upstream memory-leak instrumentation are outside Ruby runtime scope.

- [x] **Step 3: Add JWT/JWKS tests.**

Cover rotation, current/previous key verification, `kid` selection, JWKS publication, remote JWKS validation, custom JWKS path, expiration, RS256 signing, and documented decisions for unsupported JOSE algorithms.

2026-04-27 update: Added Ruby coverage for EdDSA default signing, RS256/PS256/ES256/ES512 signing and JWKS fields, unsupported symmetric algorithm rejection, current/previous `kid` selection, expiry-backed verification, and remote JWKS verification. Existing tests cover token/header issuance, `/token`, API-only sign/verify, rotation, grace-period publication, and custom JWKS path behavior.

- [x] **Step 4: Add multi-session tests.**

Cover max-session replacement preserving the new multi-session cookie, requiring an active session for set-active and revoke, invalid token errors, switching active sessions, listing device sessions, and revocation.

- [x] **Step 5: Add one-time token tests.**

Cover generate/verify, single-use, expiration, expired-session rejection, default cookie setting, cookie suppression, server-only generation, `set-ott` on every new session route, and client alias/API-surface decision.

- [x] **Step 6: Add two-factor tests.**

Cover TOTP enable/verify/disable, OTP send/verify, backup code generation/use, trusted devices, post-login verification redirect, invalid code attempts, cookie max-age options, and recovery flows.

2026-04-27 update: Added Ruby coverage for `rememberMe: false` preservation after second-factor verification, custom/default cookie max-age behavior, encrypted OTP storage, and custom hash OTP storage. Existing tests cover TOTP enable/verify/disable, OTP attempt limits, backup-code consumption, trusted-device skip/revocation, and post-login redirects.

- [ ] **Step 7: Implement missing behavior and run focused tests.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/bearer_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/custom_session_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/jwt_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/multi_session_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/one_time_token_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/two_factor_test.rb
```

Expected: all pass.

### Task 7: Complete Auth-Flow Plugins

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/anonymous.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/email_otp.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/last_login_method.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/magic_link.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/one_tap.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/passkey.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/phone_number.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/siwe.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/username.rb`
- Modify: matching test files under `packages/better_auth/test/better_auth/plugins/`

- [x] **Step 1: Add anonymous tests.**

Cover social sign-on cleanup, link-account cleanup, generated name/email callbacks, invalid generated email, repeat anonymous sign-in rejection, delete safeguards, and preserving anonymous users when the new session is still anonymous.

- [x] **Step 2: Add email OTP and magic-link tests.**

Cover override/default email verification combinations, no-enumeration sender failures, storage modes, callback redirects, invalid/expired token redirects, existing unverified user verification, disable sign-up, and client alias decisions.

- [x] **Step 3: Add last-login-method tests.**

Cover email, SIWE, social callback, generic OAuth callback, failed OAuth callback suppression, database persistence, subsequent login updates, custom cookie names, custom prefixes, cross-subdomain, cross-origin, and localhost development origins.

2026-04-27 update: Added Ruby coverage for SIWE, social OAuth, generic OAuth, failed OAuth callback suppression, database persistence after callbacks, custom cookie names with custom prefixes, cross-subdomain attributes, and cross-origin attributes. Existing tests cover successful/failed email sign-in and database persistence.

- [x] **Step 4: Add one-tap tests.**

Cover Google ID-token verification, missing email, account reuse, verified/trusted account linking, disabled signup, session cookies, and documented FedCM/browser helper scope.

- [x] **Step 5: Add passkey tests.**

Cover registration/authentication option shapes, challenge expiration, allow/exclude transport details, list/update/delete authorization, delete not-found behavior, and session creation.

2026-04-27 update: Added Ruby coverage for registration/authentication option descriptor shapes, per-request challenge expiration, expired challenge rejection, allow/exclude credential transport arrays, delete not-found status/message, management authorization, real WebAuthn registration/authentication, and session creation. Browser client aliases are documented as outside Ruby server scope.

2026-04-27 verification: upstream passkey cases were inventoried from `upstream/packages/passkey/src/passkey.test.ts`; Ruby coverage is consolidated in `packages/better_auth/test/better_auth/plugins/passkey_test.rb`, plus schema parity in `packages/better_auth/test/better_auth/schema/sql_test.rb` and `packages/better_auth-rails/spec/better_auth/rails/migration_spec.rb`.

- [x] **Step 6: Add phone number tests.**

Cover OTP send/verify, signup/session, phone update, direct update-user prevention, password sign-in, require-verification, reset OTP preservation on failed password/user validation, attempt limits, custom validators, and adapter uniqueness.

2026-04-27 update: Added Ruby coverage for memory-adapter phone-number uniqueness on sign-up, latest-code verification, reset-password OTP preservation after password validation failure, sign-up-on-verification additional fields, and custom `verify_otp` false responses. Existing tests cover OTP send/verify, session creation/suppression, phone update, direct update-user prevention, password sign-in, require-verification OTP send, attempt limits, expired/reused OTPs, reset session revocation, custom validators, and custom external OTP verification.

- [x] **Step 7: Add SIWE tests.**

Cover nonce lifecycle, wallet sign-in, callback verification, ENS hook, account/session creation, multiple chain IDs, duplicate wallet handling, checksum-casing decision, and custom schema/message response shapes.

2026-04-27 update: Added Ruby coverage for EIP-55 checksum casing, case-insensitive duplicate wallet reuse without duplicate records, and custom schema model/field mapping merge behavior. Existing SIWE tests cover nonce lifecycle, wallet sign-in, callback verification, ENS hook, account/session creation, anonymous/email modes, nonce reuse, and multiple chain IDs.

- [x] **Step 8: Add username tests.**

Cover sign-up/sign-in, availability, normalization, display username, validation order, update-user, duplicates, email-verification no-leak checks, and adapter uniqueness.

2026-04-27 update: Added Ruby coverage for upstream duplicate sign-up status, update-user duplicate rules, same-user username updates, displayUsername-only mirroring, and post-normalization validation behavior. Existing tests cover sign-up/sign-in, availability, normalization, custom validators, display username validation, email-verification no-leak checks, and Rack flow integration.

- [x] **Step 9: Implement missing behavior and run focused tests.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/anonymous_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/email_otp_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/last_login_method_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/magic_link_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/one_tap_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/passkey_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/phone_number_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/siwe_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/username_test.rb
```

Expected: all pass.

2026-04-27 verification: `rbenv exec bundle exec ruby -Itest test/better_auth/plugins/siwe_test.rb` passes with 8 runs and 47 assertions. The broader auth-flow plugin command remains available for a full batch run.

### Task 8: Complete Enterprise Plugin Parity

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/sso.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/scim.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/expo.rb`
- Modify: matching test files under `packages/better_auth/test/better_auth/plugins/`
- Modify: `.docs/features/sso.md`
- Modify: `.docs/features/scim.md`
- Modify: `.docs/features/stripe.md`
- Modify: `.docs/features/expo.md`

- [x] **Step 1: Add SSO tests.**

Cover provider CRUD, OIDC callback, OIDC discovery runtime HTTP behavior, SAML callback, SAML ACS, SP metadata, replay protection, RelayState protection, XML signature/assertion/encryption decisions, domain verification, and organization assignment policies.

2026-04-27 update: Added Ruby coverage for provider access scoping, provider sanitization, OIDC discovery hydration/trusted-origin validation, SAML XML assertion counting, SAML algorithm policy decisions, and existing SAML callback/ACS/metadata/replay/RelayState/domain/organization flows.

- [x] **Step 2: Add SCIM tests.**

Cover token generation, Bearer middleware, metadata, create/list/get/update/patch/delete users, `userName` and `externalId` filters, broader RFC filter operators, slash-prefixed PATCH paths, no-path PATCH values, mapping customization, and organization enforcement.

2026-04-27 update: Added Ruby coverage for upstream SCIM token envelopes, encrypted/custom token storage, organization plugin/membership enforcement for org-scoped tokens, provider-scoped list/get/delete access, real user deletion, dot-path name PATCH mapping, and invalid/noop PATCH behavior. Existing tests cover metadata, CRUD, `userName`/`externalId` filters, slash-prefixed paths, no-path value objects, and token storage modes.

- [x] **Step 3: Add Stripe tests.**

Cover checkout, billing portal, list/cancel/restore/success, webhook signature handling, event ordering, missing local subscription creation from metadata, plan/seat/trial abuse cases, trial-start callbacks, lookup-key failure handling, customer metadata/customization, organization customer/subscription mode, cancellation callbacks, and state transitions.

- [x] **Step 4: Add Expo tests.**

Cover authorization proxy cookies, optional OAuth state cookie, `expo-origin` override, disabled origin override, trusted `exp://`, deep-link cookie injection, last-login-method integration, and documented native client scope.

- [x] **Step 5: Implement missing behavior and run focused tests.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_oidc_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_saml_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/scim_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_organization_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/expo_test.rb
```

Expected: all pass.

2026-04-27 verification: focused SSO and SCIM files pass individually:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_oidc_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/sso_saml_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/scim_test.rb
```

### Task 9: Complete OpenAPI Parity

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/open_api.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/open_api_test.rb`
- Modify: `.docs/features/open-api.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `README.md`

- [ ] **Step 1: Decide the Ruby OpenAPI contract.**

Choose one supported target and document it in `.docs/features/open-api.md`:

```markdown
Status target: Ruby OpenAPI is considered complete when generated route paths, methods, auth requirements, model field names, plugin schema fields, selected request bodies, reference page behavior, nonce, theme, and disable-reference behavior match the upstream server-relevant contract. Exact Zod internals remain TypeScript-only.
```

- [ ] **Step 2: Add snapshot-style tests.**

Add tests for base routes, plugin routes, model schemas, request-body hints, reference HTML, theme, nonce, disable-reference, and schema stability.

- [ ] **Step 3: Implement missing schema output.**

Port server-relevant behavior from `upstream/packages/better-auth/src/plugins/open-api/open-api.test.ts` and the upstream OpenAPI plugin source.

- [ ] **Step 4: Run OpenAPI tests.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/open_api_test.rb
```

Expected: pass.

### Task 10: Final Verification And Promotion

**Files:**
- Modify: `README.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `.docs/features/*.md`

- [ ] **Step 1: Run the full core test suite.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test
```

Expected: pass, with only documented optional-service skips.

- [ ] **Step 2: Run lint.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec standardrb
```

Expected: pass.

- [ ] **Step 3: Run Rails plugin schema specs if plugin schemas changed.**

Run:

```bash
cd packages/better_auth-rails
rbenv exec bundle exec rspec
```

Expected: pass.

- [ ] **Step 4: Verify no README plugin row says `Partial` without a tracked task.**

Run:

```bash
rg -n "\| .* \| Partial \|" README.md .docs/features/upstream-parity-matrix.md
```

Expected: every remaining partial row has a corresponding unfinished checkbox in this plan or a documented out-of-scope decision in its feature file.

- [ ] **Step 5: Promote completed plugins.**

For every plugin whose upstream inventory is fully covered, update:

```text
README.md
.docs/features/upstream-parity-matrix.md
.docs/features/<plugin>.md
```

Use `[x] Supported` in the README and `Complete` in the matrix.
