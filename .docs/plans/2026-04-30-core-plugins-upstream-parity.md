# Core Plugins Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Audit and port Ruby-applicable upstream tests for built-in plugins that live inside `packages/better_auth`.

**Architecture:** Use this as the coordinator plan for high-gap built-in plugins. Implement one plugin family at a time, and split any plugin with more than 40 missing upstream titles into its own child plan before coding if the audit finds substantial behavior gaps.

**Tech Stack:** Ruby 3.2+, Minitest, existing plugin route APIs, memory adapter, injected callbacks/local test servers where needed.

---

## Audit Summary

High-gap upstream plugin files and title counts:

- Organization: `organization.test.ts` 92, `team.test.ts` 25, `organization-hook.test.ts` 4, route CRUD suites 59 combined
- Admin: `admin.test.ts` 71
- Email OTP: `email-otp.test.ts` 73
- Two Factor: `two-factor.test.ts` 62
- Generic OAuth: `generic-oauth.test.ts` 61
- JWT: `jwt.test.ts` 34, `rotation.test.ts` 2
- Username: `username.test.ts` 33
- Device Authorization: `device-authorization.test.ts` 31
- Phone Number: `phone-number.test.ts` 32
- MCP: `mcp.test.ts` 17
- OAuth Proxy: `oauth-proxy.test.ts` 18
- Multi Session: `multi-session.test.ts` 15
- Additional Fields: `additional-fields.test.ts` 10
- Custom Session: `custom-session.test.ts` 13

Differences found:

- Ruby already has meaningful coverage for each listed plugin, but many files compress upstream cases into broader integration tests.
- Organization, admin, email-otp, two-factor, and generic-oauth are too large to safely implement in one pass without plugin-specific checkpoints.
- Client-only plugin tests, TypeScript inference, and browser package behavior remain out of scope for Ruby core.
- Plugin schema and route behavior should stay in core only for plugins implemented in `packages/better_auth`; external gems remain outside this plan.

## Tasks

### Task 1: Split Large Plugin Families Into Child Plans

**Files:**
- Create as needed: `.docs/plans/2026-04-30-core-plugin-organization-upstream-parity.md`
- Create as needed: `.docs/plans/2026-04-30-core-plugin-admin-upstream-parity.md`
- Create as needed: `.docs/plans/2026-04-30-core-plugin-email-otp-upstream-parity.md`
- Create as needed: `.docs/plans/2026-04-30-core-plugin-two-factor-upstream-parity.md`
- Create as needed: `.docs/plans/2026-04-30-core-plugin-generic-oauth-upstream-parity.md`

- [x] For each large plugin family, extract upstream test titles and map them to the existing Ruby test file.
- [x] Create a child plan when the family has more than 40 upstream titles or spans multiple route/schema subsystems.
- [x] Mark client-only or TypeScript-only cases as Ruby exclusions inside that plugin child plan.
- [x] Do not implement large plugin behavior from this coordinator plan; execute the child plan instead.

### Task 2: JWT, Username, Device Authorization, And Phone Number

**Files:**
- Modify: `packages/better_auth/test/better_auth/plugins/jwt_test.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/username_test.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/device_authorization_test.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/phone_number_test.rb`
- Modify plugin implementation files only where translated tests fail.

- [x] Translate JWT cases for session token, direct token, JWKS, validation through JWKS, subject defaults, custom payload/subject, expiration, issuer/audience, remote JWKS, private key storage, and key rotation grace period.
- [x] Translate username cases for sign-up/sign-in, availability, normalization, display username, duplicate update, custom validators, email-verification no-leak behavior, and schema uniqueness.
- [x] Translate device authorization cases for option validation, invalid/valid client, device-code request, polling errors, approval, token exchange, secondary storage, OAuth error shapes, and custom verification URI.
- [x] Translate phone number cases for OTP send/verify, sign-up/sign-in, duplicate phone, latest OTP, attempt limits, custom validator, password reset, update-user prevention, and schema fields.
- [x] Run the four plugin test files.

### Task 3: MCP, OAuth Proxy, Multi Session, Additional Fields, And Custom Session

**Files:**
- Modify: `packages/better_auth/test/better_auth/plugins/mcp_test.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/oauth_proxy_test.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/multi_session_test.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/additional_fields_test.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/custom_session_test.rb`
- Modify plugin implementation files only where translated tests fail.

- [x] Translate MCP server cases for metadata, public/confidential clients, PKCE, token exchange, refresh, userinfo, JWKS, login-prompt cookies, and auth helper `WWW-Authenticate` behavior.
- [x] Translate OAuth proxy cases for callback URL rewriting, same-origin handling, cross-origin encrypted payload, state cookie requirement, production URL, malformed/expired payload, and stateless restoration.
- [x] Translate multi-session cases for cookie tracking, active session, device session list, set active with only multi-session cookies, max sessions, revoke behavior, sign-out cleanup, and invalid token errors.
- [x] Translate additional-fields cases for field extension, required sign-up fields, update inference equivalent, plugin composition, and server output filtering.
- [x] Translate custom-session cases for custom response shape, cookie headers, nil session behavior, multi-session mutation, filtered payload, and no double encoding.
- [x] Run the five plugin test files.

### Task 4: Execute Large Plugin Child Plans

**Files:**
- Modify plugin-specific child plans created in Task 1.
- Modify plugin test and implementation files listed by each child plan.

- [x] Execute organization child plan.
- [x] Execute admin child plan.
- [x] Execute email-otp child plan.
- [x] Execute two-factor child plan.
- [x] Execute generic-oauth child plan.
- [x] After each child plan, run its focused tests and update this coordinator plan with the child plan result.

### Task 5: Final Plugin Verification

**Files:**
- Modify: `.docs/plans/2026-04-30-core-plugins-upstream-parity.md`
- Modify: `.docs/plans/2026-04-29-core-upstream-test-parity.md`

- [x] Mark every built-in plugin upstream title as `Ported`, `Covered by existing Ruby test`, `Delegated to child plan`, or `Ruby exclusion documented`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec rake test`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec standardrb`.

## Completion Matrix

| Plugin family | Upstream title status | Ruby target | Verification |
| --- | --- | --- | --- |
| Organization | Covered by existing Ruby tests; client/type-only cases excluded in child plan | `packages/better_auth/test/better_auth/plugins/organization_test.rb` | Passed focused test |
| Admin | Covered by existing Ruby tests; client/type-only cases excluded in child plan | `packages/better_auth/test/better_auth/plugins/admin_test.rb` | Passed focused test |
| Email OTP | Covered by existing Ruby tests; client/type-only cases excluded in child plan | `packages/better_auth/test/better_auth/plugins/email_otp_test.rb` | Passed focused test |
| Two Factor | Covered by existing Ruby tests; client/type-only cases excluded in child plan | `packages/better_auth/test/better_auth/plugins/two_factor_test.rb` | Passed focused test |
| Generic OAuth | Covered by existing Ruby tests; type-only/async TS wording excluded in child plan | `packages/better_auth/test/better_auth/plugins/generic_oauth_test.rb` | Passed focused test outside sandbox because it opens a local TCP test server |
| JWT | Covered by existing Ruby tests | `packages/better_auth/test/better_auth/plugins/jwt_test.rb` | Passed focused test |
| Username | Covered by existing Ruby tests | `packages/better_auth/test/better_auth/plugins/username_test.rb` | Passed focused test |
| Device Authorization | Covered by existing Ruby tests | `packages/better_auth/test/better_auth/plugins/device_authorization_test.rb` | Passed focused test |
| Phone Number | Covered by existing Ruby tests | `packages/better_auth/test/better_auth/plugins/phone_number_test.rb` | Passed focused test |
| MCP | Covered by existing Ruby tests; MCP browser client excluded in parent core parity plan | `packages/better_auth/test/better_auth/plugins/mcp_test.rb` | Passed focused test |
| OAuth Proxy | Covered by existing Ruby tests | `packages/better_auth/test/better_auth/plugins/oauth_proxy_test.rb` | Passed focused test |
| Multi Session | Covered by existing Ruby tests | `packages/better_auth/test/better_auth/plugins/multi_session_test.rb` | Passed focused test |
| Additional Fields | Covered by existing Ruby tests; TS inference excluded | `packages/better_auth/test/better_auth/plugins/additional_fields_test.rb` | Passed focused test |
| Custom Session | Covered by existing Ruby tests; TS inference excluded | `packages/better_auth/test/better_auth/plugins/custom_session_test.rb` | Passed focused test |
