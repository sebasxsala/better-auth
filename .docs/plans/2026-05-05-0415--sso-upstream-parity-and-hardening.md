# SSO Upstream Parity and Hardening Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` or `subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining high-value `better_auth-sso` gaps against upstream `v1.6.9`: hook parity, provider schema option parity, provider update validation, SAML Single Logout hardening, and documentation.

**Architecture:** Keep behavior localized to `packages/better_auth-sso`. Preserve Ruby's current default SSO provider model name, `ssoProviders`, for backward compatibility even though upstream defaults to `ssoProvider`.

**Tech Stack:** Ruby 3.2+, Better Auth Ruby plugin APIs, Minitest, `ruby-saml`.

---

## Tasks

- [x] Add SSO plugin hooks in `packages/better_auth-sso/lib/better_auth/plugins/sso.rb`:
  - [x] Before `/sign-out`, when `saml.enable_single_logout` is enabled, delete `saml-session-by-id:<session_token>` and the referenced SAML session verification record before core sign-out deletes the session.
  - [x] After generic `/callback/*`, when `ctx.context.new_session` exists and the organization plugin is enabled, assign organization membership by verified SSO domain.
  - [x] Keep the callback matcher narrow so `/sso/callback` and SAML ACS routes are not handled as generic OAuth callbacks.
- [x] Improve SSO provider schema parity in `packages/better_auth-sso/lib/better_auth/sso/routes/schemas.rb`:
  - [x] Support `fields:` mappings for all upstream SSO provider fields, including `domainVerified`.
  - [x] Add `references: {model: "user", field: "id"}` to `userId`.
  - [x] Preserve `model_name: "ssoProviders"` as the Ruby default.
- [x] Harden `/sso/update-provider`:
  - [x] Validate SAML metadata size and algorithms when `saml_config` is updated.
  - [x] Merge updated SAML/OIDC config with the resolved issuer so stored config does not drift from provider issuer.
  - [x] Preserve partial update behavior and sanitized responses.
- [x] Tighten SAML Single Logout:
  - [x] Reject unsigned inbound LogoutRequest/LogoutResponse when signed SLO is required and no valid `Signature` is present.
  - [x] Include `InResponseTo` when generating LogoutResponse for IdP LogoutRequest.
  - [x] Keep the lightweight fallback for tests/configurations that do not require signed SLO validation.
- [x] Update `packages/better_auth-sso/README.md`:
  - [x] Document current capabilities.
  - [x] Document the intentional `ssoProviders` default.
  - [x] Document that production XML SAML deployments should configure `BetterAuth::SSO::SAML.sso_options`.
  - [x] Mention domain-based organization assignment on generic OAuth callbacks.
- [x] Verify with:
  - [x] `cd packages/better_auth-sso && rbenv exec bundle exec rake test`
  - [x] `cd packages/better_auth-sso && rbenv exec bundle exec standardrb`

## Notes

- Do not bump `better_auth-sso` version unless this work is being released.
- Existing unrelated deleted files in `.docs/` and unrelated package edits are not part of this plan.
- 2026-05-05: Implemented inline on branch `canary`. Ruby-specific adaptation: signed SLO hardening currently rejects missing signatures when signed inbound SLO is required and keeps the existing lightweight fallback for unsigned configurations.
