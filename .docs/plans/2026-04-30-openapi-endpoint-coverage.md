# OpenAPI Endpoint Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Document every public BetterAuth Ruby endpoint in OpenAPI by colocating `metadata[:openapi]` on each `Endpoint.new`, matching upstream Better Auth v1.6.9 behavior where available.

**Architecture:** Keep `BetterAuth::Plugins.open_api` as a generic collector that reads endpoint metadata and model schemas. Add endpoint-specific OpenAPI metadata next to each route implementation, using `BetterAuth::OpenAPI` helpers for common response and schema shapes. Do not reintroduce a route/path `case` table in `open_api.rb`.

**Tech Stack:** Ruby, Rack, Minitest, StandardRB, local upstream TypeScript source under `upstream/packages/better-auth/src`.

---

## Current Status

Completed direct `metadata[:openapi]` coverage:

- [x] Core `POST /sign-in/email` in `packages/better_auth/lib/better_auth/routes/sign_in.rb`
- [x] Core `POST /sign-up/email` in `packages/better_auth/lib/better_auth/routes/sign_up.rb`
- [x] Core `POST /sign-in/social` in `packages/better_auth/lib/better_auth/routes/social.rb`
- [x] Core `POST /change-password` in `packages/better_auth/lib/better_auth/routes/user.rb`
- [x] Core `POST /change-email` in `packages/better_auth/lib/better_auth/routes/user.rb`
- [x] Plugin override `GET /get-session` in `packages/better_auth/lib/better_auth/plugins/custom_session.rb`
- [x] Plugin `POST /one-tap/callback` in `packages/better_auth/lib/better_auth/plugins/one_tap.rb`

Intentionally excluded from public OpenAPI unless product policy changes:

- [x] Hidden health/error routes: `GET /ok`, `GET /error`
- [x] OpenAPI plugin self routes: `GET /open-api/generate-schema`, configured reference route
- [x] Hidden discovery routes already marked `metadata: {hide: true}`: MCP and OIDC well-known endpoints
- [x] Pathless/internal endpoints: JWT `sign_jwt`, JWT `verify_jwt`, Email OTP create-verification helper, Two Factor view-backup-codes helper

## Upstream References

Use these upstream files before adding metadata for the matching Ruby endpoint:

- Core routes: `upstream/packages/better-auth/src/api/routes/*.ts`
- OpenAPI generator behavior: `upstream/packages/better-auth/src/plugins/open-api/generator.ts`
- Admin: `upstream/packages/better-auth/src/plugins/admin/routes.ts`
- Anonymous: `upstream/packages/better-auth/src/plugins/anonymous/index.ts`
- Custom Session: `upstream/packages/better-auth/src/plugins/custom-session/index.ts`
- Device Authorization: `upstream/packages/better-auth/src/plugins/device-authorization/routes.ts`
- Email OTP: `upstream/packages/better-auth/src/plugins/email-otp/routes.ts`
- Generic OAuth: `upstream/packages/better-auth/src/plugins/generic-oauth/routes.ts`
- JWT: `upstream/packages/better-auth/src/plugins/jwt/index.ts`
- Magic Link: `upstream/packages/better-auth/src/plugins/magic-link/index.ts`
- MCP: `upstream/packages/better-auth/src/plugins/mcp/index.ts`
- Multi Session: `upstream/packages/better-auth/src/plugins/multi-session/index.ts`
- OAuth Proxy: `upstream/packages/better-auth/src/plugins/oauth-proxy/index.ts`
- OIDC Provider: `upstream/packages/better-auth/src/plugins/oidc-provider/index.ts`
- One Time Token: `upstream/packages/better-auth/src/plugins/one-time-token/index.ts`
- Organization: `upstream/packages/better-auth/src/plugins/organization/**/*`
- Phone Number: `upstream/packages/better-auth/src/plugins/phone-number/routes.ts`
- SIWE: `upstream/packages/better-auth/src/plugins/siwe/index.ts`
- Two Factor: `upstream/packages/better-auth/src/plugins/two-factor/**/*`
- Username: `upstream/packages/better-auth/src/plugins/username/index.ts`

## Implementation Rules

- [x] Keep endpoint OpenAPI metadata colocated with the `Endpoint.new` call.
- [x] Keep `packages/better_auth/lib/better_auth/plugins/open_api.rb` free of route-specific branching.
- [x] Prefer upstream request/response descriptions and operation IDs exactly when the Ruby behavior matches.
- [x] When Ruby behavior intentionally differs from upstream, document the Ruby behavior and add a note in this plan.
- [x] Add or update Minitest coverage before each batch implementation.
- [x] After each batch, run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/open_api_test.rb
rbenv exec bundle exec standardrb lib/better_auth/plugins/open_api.rb test/better_auth/plugins/open_api_test.rb
```

- [x] Before closing the full plan, run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test
rbenv exec bundle exec standardrb
```

## Coverage Guard Task

**Files:**
- Modify: `packages/better_auth/test/better_auth/plugins/open_api_test.rb`
- Optionally modify: `packages/better_auth/lib/better_auth/plugins/open_api.rb`

- [x] Add a generic default metadata path for pathful, non-hidden endpoints without explicit `metadata[:openapi]`.
- [x] Add test coverage proving default metadata is attached to an otherwise-undocumented plugin endpoint.
- [x] Verify the new test fails before adding default metadata.
- [x] Keep explicit route checklists below as the main rich-schema parity mechanism.

Ruby-specific adaptation: unlike upstream, Ruby does not yet have an introspectable Zod-equivalent schema for every endpoint. To prevent public endpoints from being entirely undocumented while rich per-route schemas are ported, `BetterAuth::Endpoint` now attaches generic OpenAPI metadata for pathful, non-hidden endpoints that do not provide explicit metadata. Rich upstream parity is still tracked by the endpoint checklists below.

## Core Route Checklist

### Already completed

- [x] `POST /sign-in/email` -> upstream `src/api/routes/sign-in.ts`
- [x] `POST /sign-up/email` -> upstream `src/api/routes/sign-up.ts`
- [x] `POST /sign-in/social` -> upstream `src/api/routes/sign-in.ts`
- [x] `POST /change-password` -> upstream `src/api/routes/update-user.ts`
- [x] `POST /change-email` -> upstream `src/api/routes/update-user.ts`

### Pending core routes

- [x] `GET|POST /get-session` in `packages/better_auth/lib/better_auth/routes/session.rb`
- [x] `GET /list-sessions` in `packages/better_auth/lib/better_auth/routes/session.rb`
- [x] `POST /update-session` in `packages/better_auth/lib/better_auth/routes/session.rb`
- [x] `POST /revoke-session` in `packages/better_auth/lib/better_auth/routes/session.rb`
- [x] `POST /revoke-sessions` in `packages/better_auth/lib/better_auth/routes/session.rb`
- [x] `POST /revoke-other-sessions` in `packages/better_auth/lib/better_auth/routes/session.rb`
- [x] `POST /sign-out` in `packages/better_auth/lib/better_auth/routes/sign_out.rb`
- [x] `POST /send-verification-email` in `packages/better_auth/lib/better_auth/routes/email_verification.rb`
- [x] `GET /verify-email` in `packages/better_auth/lib/better_auth/routes/email_verification.rb`
- [x] `POST /request-password-reset` in `packages/better_auth/lib/better_auth/routes/password.rb`
- [x] `GET /reset-password/:token` in `packages/better_auth/lib/better_auth/routes/password.rb`
- [x] `POST /reset-password` in `packages/better_auth/lib/better_auth/routes/password.rb`
- [x] `POST /verify-password` in `packages/better_auth/lib/better_auth/routes/password.rb`
- [x] `POST /update-user` in `packages/better_auth/lib/better_auth/routes/user.rb`
- [x] `POST /set-password` in `packages/better_auth/lib/better_auth/routes/user.rb`
- [x] `POST /delete-user` in `packages/better_auth/lib/better_auth/routes/user.rb`
- [x] `GET /delete-user/callback` in `packages/better_auth/lib/better_auth/routes/user.rb`
- [x] `GET|POST /callback/:id` in `packages/better_auth/lib/better_auth/routes/social.rb`
- [x] `POST /link-social` in `packages/better_auth/lib/better_auth/routes/social.rb`
- [x] `GET /list-accounts` in `packages/better_auth/lib/better_auth/routes/account.rb`
- [x] `POST /unlink-account` in `packages/better_auth/lib/better_auth/routes/account.rb`
- [x] `POST /get-access-token` in `packages/better_auth/lib/better_auth/routes/account.rb`
- [x] `POST /refresh-token` in `packages/better_auth/lib/better_auth/routes/account.rb`
- [x] `GET /account-info` in `packages/better_auth/lib/better_auth/routes/account.rb`

## Plugin Route Checklist

### Admin

- [x] `POST /admin/set-role` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `GET /admin/get-user` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `POST /admin/create-user` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `POST /admin/update-user` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `GET /admin/list-users` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `POST /admin/list-user-sessions` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `POST /admin/ban-user` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `POST /admin/unban-user` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `POST /admin/impersonate-user` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `POST /admin/stop-impersonating` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `POST /admin/revoke-user-session` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `POST /admin/revoke-user-sessions` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `POST /admin/remove-user` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `POST /admin/set-user-password` in `packages/better_auth/lib/better_auth/plugins/admin.rb`
- [x] `POST /admin/has-permission` in `packages/better_auth/lib/better_auth/plugins/admin.rb`

### Anonymous

- [x] `POST /sign-in/anonymous` in `packages/better_auth/lib/better_auth/plugins/anonymous.rb`
- [x] `POST /delete-anonymous-user` in `packages/better_auth/lib/better_auth/plugins/anonymous.rb`

### Custom Session

- [x] `GET /get-session` override in `packages/better_auth/lib/better_auth/plugins/custom_session.rb`

### Device Authorization

- [x] `POST /device/code` in `packages/better_auth/lib/better_auth/plugins/device_authorization.rb`
- [x] `POST /device/token` in `packages/better_auth/lib/better_auth/plugins/device_authorization.rb`
- [x] `GET /device` in `packages/better_auth/lib/better_auth/plugins/device_authorization.rb`
- [x] `POST /device/approve` in `packages/better_auth/lib/better_auth/plugins/device_authorization.rb`
- [x] `POST /device/deny` in `packages/better_auth/lib/better_auth/plugins/device_authorization.rb`

### Dub

- [x] `POST /dub/link` in `packages/better_auth/lib/better_auth/plugins/dub.rb`

### Email OTP

- [x] `POST /email-otp/send-verification-otp` in `packages/better_auth/lib/better_auth/plugins/email_otp.rb`
- [x] `GET /email-otp/get-verification-otp` in `packages/better_auth/lib/better_auth/plugins/email_otp.rb`
- [x] `POST /email-otp/check-verification-otp` in `packages/better_auth/lib/better_auth/plugins/email_otp.rb`
- [x] `POST /email-otp/verify-email` in `packages/better_auth/lib/better_auth/plugins/email_otp.rb`
- [x] `POST /sign-in/email-otp` in `packages/better_auth/lib/better_auth/plugins/email_otp.rb`
- [x] `POST /email-otp/request-email-change` in `packages/better_auth/lib/better_auth/plugins/email_otp.rb`
- [x] `POST /email-otp/change-email` in `packages/better_auth/lib/better_auth/plugins/email_otp.rb`
- [x] `POST /email-otp/request-password-reset` in `packages/better_auth/lib/better_auth/plugins/email_otp.rb`
- [x] `POST /forget-password/email-otp` in `packages/better_auth/lib/better_auth/plugins/email_otp.rb`
- [x] `POST /email-otp/reset-password` in `packages/better_auth/lib/better_auth/plugins/email_otp.rb`
- [x] Internal pathless create-verification OTP endpoint: kept excluded because it has no public HTTP path.

### Expo

- [x] `GET /expo-authorization-proxy` in `packages/better_auth/lib/better_auth/plugins/expo.rb`

### Generic OAuth

- [x] `POST /sign-in/oauth2` in `packages/better_auth/lib/better_auth/plugins/generic_oauth.rb`
- [x] `POST /oauth2/link` in `packages/better_auth/lib/better_auth/plugins/generic_oauth.rb`
- [x] `GET /oauth2/callback/:providerId` in `packages/better_auth/lib/better_auth/plugins/generic_oauth.rb`

### JWT

- [x] `GET <configured jwks path>` in `packages/better_auth/lib/better_auth/plugins/jwt.rb`
- [x] `GET /token` in `packages/better_auth/lib/better_auth/plugins/jwt.rb`
- [x] Internal pathless sign JWT endpoint: kept excluded because it has no public HTTP path.
- [x] Internal pathless verify JWT endpoint: kept excluded because it has no public HTTP path.

### Magic Link

- [x] `POST /sign-in/magic-link` in `packages/better_auth/lib/better_auth/plugins/magic_link.rb`
- [x] `GET /magic-link/verify` in `packages/better_auth/lib/better_auth/plugins/magic_link.rb`

### MCP

- [x] `POST /mcp/register` in `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- [x] `GET /mcp/authorize` in `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- [x] `POST /mcp/token` in `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- [x] `GET /mcp/userinfo` in `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- [x] `GET /mcp/get-session` in `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- [x] `GET /mcp/jwks` in `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- [x] Hidden `GET /.well-known/oauth-authorization-server`: kept hidden.
- [x] Hidden `GET /.well-known/oauth-protected-resource`: kept hidden.

### Multi Session

- [x] `GET /multi-session/list-device-sessions` in `packages/better_auth/lib/better_auth/plugins/multi_session.rb`
- [x] `POST /multi-session/set-active` in `packages/better_auth/lib/better_auth/plugins/multi_session.rb`
- [x] `POST /multi-session/revoke` in `packages/better_auth/lib/better_auth/plugins/multi_session.rb`

### OAuth Proxy

- [x] `GET /oauth-proxy-callback` in `packages/better_auth/lib/better_auth/plugins/oauth_proxy.rb`

### OIDC Provider

- [x] `POST /oauth2/register` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] `GET /oauth2/client/:id` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] `GET /oauth2/clients` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] `PATCH /oauth2/client/:id` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] `POST /oauth2/client/:id/rotate-secret` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] `DELETE /oauth2/client/:id` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] `GET /oauth2/authorize` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] `POST /oauth2/consent` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] `POST /oauth2/token` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] `GET /oauth2/userinfo` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] `POST /oauth2/introspect` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] `POST /oauth2/revoke` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] `GET|POST /oauth2/endsession` in `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- [x] Hidden `GET /.well-known/openid-configuration`: kept hidden.

### One Tap

- [x] `POST /one-tap/callback` in `packages/better_auth/lib/better_auth/plugins/one_tap.rb`

### One Time Token

- [x] `GET /one-time-token/generate` in `packages/better_auth/lib/better_auth/plugins/one_time_token.rb`
- [x] `POST /one-time-token/verify` in `packages/better_auth/lib/better_auth/plugins/one_time_token.rb`

### Organization

- [x] `POST /organization/create` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/check-slug` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/list` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/update` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/delete` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/set-active` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/get-full-organization` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/invite-member` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/accept-invitation` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/reject-invitation` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/cancel-invitation` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/get-invitation` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/list-invitations` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/list-user-invitations` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/add-member` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/remove-member` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/update-member-role` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/get-active-member` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/get-active-member-role` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/leave` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/list-members` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/has-permission` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/create-team` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/list-teams` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/update-team` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/remove-team` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/set-active-team` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/list-user-teams` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/list-team-members` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/add-team-member` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/remove-team-member` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/create-role` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/list-roles` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `GET /organization/get-role` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/update-role` in `packages/better_auth/lib/better_auth/plugins/organization.rb`
- [x] `POST /organization/delete-role` in `packages/better_auth/lib/better_auth/plugins/organization.rb`

### Phone Number

- [x] `POST /sign-in/phone-number` in `packages/better_auth/lib/better_auth/plugins/phone_number.rb`
- [x] `POST /phone-number/send-otp` in `packages/better_auth/lib/better_auth/plugins/phone_number.rb`
- [x] `POST /phone-number/verify` in `packages/better_auth/lib/better_auth/plugins/phone_number.rb`
- [x] `POST /phone-number/request-password-reset` in `packages/better_auth/lib/better_auth/plugins/phone_number.rb`
- [x] `POST /phone-number/reset-password` in `packages/better_auth/lib/better_auth/plugins/phone_number.rb`

### SIWE

- [x] `POST /siwe/nonce` in `packages/better_auth/lib/better_auth/plugins/siwe.rb`
- [x] `POST /siwe/verify` in `packages/better_auth/lib/better_auth/plugins/siwe.rb`

### Two Factor

- [x] `POST /two-factor/enable` in `packages/better_auth/lib/better_auth/plugins/two_factor.rb`
- [x] `POST /two-factor/disable` in `packages/better_auth/lib/better_auth/plugins/two_factor.rb`
- [x] `POST /totp/generate` in `packages/better_auth/lib/better_auth/plugins/two_factor.rb`
- [x] `POST /two-factor/get-totp-uri` in `packages/better_auth/lib/better_auth/plugins/two_factor.rb`
- [x] `POST /two-factor/verify-totp` in `packages/better_auth/lib/better_auth/plugins/two_factor.rb`
- [x] `POST /two-factor/send-otp` in `packages/better_auth/lib/better_auth/plugins/two_factor.rb`
- [x] `POST /two-factor/verify-otp` in `packages/better_auth/lib/better_auth/plugins/two_factor.rb`
- [x] `POST /two-factor/verify-backup-code` in `packages/better_auth/lib/better_auth/plugins/two_factor.rb`
- [x] `POST /two-factor/generate-backup-codes` in `packages/better_auth/lib/better_auth/plugins/two_factor.rb`
- [x] Internal pathless view-backup-codes endpoint: kept excluded because it has no public HTTP path.

### Username

- [x] `POST /sign-in/username` in `packages/better_auth/lib/better_auth/plugins/username.rb`
- [x] `POST /is-username-available` in `packages/better_auth/lib/better_auth/plugins/username.rb`

## Batch Execution Order

### Task 1: Coverage guard and helper cleanup

**Files:**
- Modify: `packages/better_auth/test/better_auth/plugins/open_api_test.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/open_api.rb`

- [x] Write failing coverage test for pathful endpoints missing `metadata[:openapi]`.
- [x] Add explicit skip reason structure for hidden/pathless endpoints in the test.
- [x] Add missing `BetterAuth::OpenAPI` helpers only when they remove repeated schema noise.
- [x] Run the OpenAPI test file and confirm the coverage test fails with the pending endpoint list.
- [ ] Commit the test guard and helper-only changes.

### Task 2: Core endpoint metadata

**Files:**
- Modify: `packages/better_auth/lib/better_auth/routes/session.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/sign_out.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/email_verification.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/password.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/user.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/social.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/account.rb`
- Test: `packages/better_auth/test/better_auth/plugins/open_api_test.rb`

- [x] Port upstream OpenAPI metadata from `upstream/packages/better-auth/src/api/routes`.
- [x] Mark each completed core route checkbox above.
- [x] Add assertions for representative core endpoints: session, password reset, update user, account, OAuth callback.
- [x] Run `rbenv exec bundle exec ruby -Itest test/better_auth/plugins/open_api_test.rb`.
- [x] Run `rbenv exec bundle exec standardrb lib/better_auth/routes test/better_auth/plugins/open_api_test.rb`.
- [ ] Commit the core metadata batch.

### Task 3: Authentication plugin metadata

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/anonymous.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/magic_link.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/email_otp.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/phone_number.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/username.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/siwe.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/one_time_token.rb`
- Test: `packages/better_auth/test/better_auth/plugins/open_api_test.rb`

- [x] Port upstream metadata for the listed plugin routes.
- [x] For plugin options that conditionally add routes, add tests with the plugin enabled.
- [x] Mark each completed authentication plugin route checkbox above.
- [x] Run OpenAPI tests and StandardRB for touched files.
- [ ] Commit the authentication plugin metadata batch.

### Task 4: Admin, organization, and multi-session metadata

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/admin.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/organization.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/multi_session.rb`
- Test: `packages/better_auth/test/better_auth/plugins/open_api_test.rb`

- [x] Port upstream admin route metadata from `upstream/packages/better-auth/src/plugins/admin/routes.ts`.
- [x] Port upstream organization metadata from `upstream/packages/better-auth/src/plugins/organization`.
- [x] Port upstream multi-session metadata from `upstream/packages/better-auth/src/plugins/multi-session/index.ts`.
- [x] Add representative tests for admin list users, organization create/list, and multi-session revoke.
- [x] Mark each completed route checkbox above.
- [x] Run OpenAPI tests and StandardRB for touched files.
- [ ] Commit this plugin batch.

Ruby-specific adaptation: organization route metadata uses upstream operation IDs where upstream defines them, and Ruby-native names for routes where upstream relies on generated operation IDs. The OpenAPI response shapes are intentionally compact refs to the Ruby model components instead of duplicating every conditional plugin schema inline.

### Task 5: OAuth/OIDC/MCP/JWT/device metadata

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/generic_oauth.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_proxy.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/jwt.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/device_authorization.rb`
- Test: `packages/better_auth/test/better_auth/plugins/open_api_test.rb`

- [x] Port upstream metadata for public routes.
- [x] Decide and document whether discovery endpoints stay hidden.
- [x] Decide and document whether pathless JWT endpoints stay excluded.
- [x] Add representative tests for `/token`, `/oauth2/token`, `/mcp/register`, and `/device/code`.
- [x] Mark each completed route checkbox above.
- [x] Run OpenAPI tests and StandardRB for touched files.
- [ ] Commit this plugin batch.

Ruby-specific adaptation: OAuth/OIDC/MCP response schemas are compact Ruby OpenAPI objects that preserve public operation IDs, descriptions, content types, and success shapes without copying every upstream Zod branch.

### Task 6: Remaining small plugins and final audit

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/dub.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/expo.rb`
- Modify: any optional plugin file added during the audit
- Test: `packages/better_auth/test/better_auth/plugins/open_api_test.rb`
- Modify: this plan file

- [x] Add metadata for Dub and Expo routes.
- [x] Re-run the endpoint inventory command:

```bash
rg -n "Endpoint\\.new" packages/better_auth/lib/better_auth -g "*.rb"
```

- [x] Verify every public pathful endpoint is either checked above or has an explicit skip reason.
- [x] Run full package tests and StandardRB.
- [x] Update this plan so all completed route checkboxes are checked.
- [ ] Commit the final audit.

Final verification on 2026-04-30:

- `rbenv exec bundle exec rake test`: 749 runs, 3979 assertions, 0 failures, 0 errors, 0 skips.
- `rbenv exec bundle exec standardrb`: passed.
