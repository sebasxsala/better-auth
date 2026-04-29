# Plugin Parity Gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close server-side upstream parity gaps for last-login-method, magic-link, MCP, and multi-session in `packages/better_auth`.

**Architecture:** Keep all four plugins in the core Rack-only gem and reuse existing OAuth/OIDC helpers where possible. TypeScript browser/client helpers remain documented as outside the Ruby server surface.

**Tech Stack:** Ruby, Rack, Minitest, Better Auth internal adapter and plugin APIs.

---

2026-04-28 note: `.docs/plans/2026-04-25-better-auth-ruby-port.md` is still referenced by repository instructions but is not present in this checkout. This plan records the current plugin-parity implementation pass.

### Task 1: Last Login Method

- [x] Add tests for magic-link cookie/database tracking, upstream schema field naming, and missing-path custom resolver normalization.
- [x] Resolve `/magic-link/verify` as `magic-link`.
- [x] Use `lastLoginMethod` as the default physical field name.
- [x] Normalize missing hook paths before invoking `custom_resolve_method`.

### Task 2: Magic Link

- [x] Add tests for metadata forwarding, verify JSON `session`, default attempt exhaustion, bounded attempts, and unlimited attempts.
- [x] Add `allowed_attempts` with default `1` and `Float::INFINITY` support.
- [x] Store and increment verification `attempt` values, deleting verification records after attempts are exceeded or expired.
- [x] Forward `metadata` to `send_magic_link`.
- [x] Include parsed session data in JSON verify responses.

### Task 3: Multi Session

- [x] Add tests for set-active with only signed multi-session cookies and revocation fallback ignoring expired sessions.
- [x] Remove active-session requirement from set-active.
- [x] Keep revoke protected by the active session requirement.
- [x] Only activate non-expired fallback sessions after revoking the active session.
- [x] Only set multi-session cookies when the response sets a session cookie.
- [x] Only clear verified signed multi-session cookies on sign-out and canonicalize `__Secure-`.

### Task 4: MCP

- [x] Add tests for `/mcp/get-session`, token-validating `with_mcp_auth`, confidential clients, Basic auth, invalid response types, invalid scopes, and PKCE-required redirects.
- [x] Add `/mcp/get-session`.
- [x] Validate bearer tokens in `with_mcp_auth` through `auth.api.get_mcp_session`.
- [x] Validate MCP authorize requests for response type, redirect URI, client disabled state, scopes, and PKCE.
- [x] Validate MCP token requests for public vs confidential clients and Basic auth.
- [x] Reuse OIDC consent storage/endpoint for `prompt=consent`.

### Task 5: Documentation and Verification

- [x] Update feature docs for the four plugins.
- [x] Update `.docs/features/upstream-parity-matrix.md`.
- [x] Run focused plugin tests.
- [x] Run the package test suite. Current full-suite failures are outside this plugin-parity change and remain in `additional_fields`, `organization`, and `api_key`.
