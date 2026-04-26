# Phase 9 Security Plugins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Port Better Auth security plugins into the Ruby core gem: `two-factor`, `captcha`, `haveibeenpwned`, and `api-key`.

**Architecture:** Security plugins are regular `BetterAuth::Plugin` instances that add schema, endpoints, hooks, request middleware, and error codes through the existing plugin contract. External verification calls use stdlib HTTP and are stubbed in tests.

**Tech Stack:** Ruby 3.2+, Rack 3, Minitest, StandardRB, stdlib `Net::HTTP`, `OpenSSL`, `Base64`, `JSON`, `URI`.

---

## Upstream References

- `upstream/packages/better-auth/src/plugins/two-factor/**`
- `upstream/packages/better-auth/src/plugins/captcha/**`
- `upstream/packages/better-auth/src/plugins/haveibeenpwned/**`
- `upstream/packages/better-auth/src/plugins/api-key/**`

## Tasks

- [x] Add requires for the four plugins to `packages/better_auth/lib/better_auth.rb`.
- [x] Implement `BetterAuth::Plugins.two_factor` with schema, TOTP, OTP, backup codes, trusted-device cookies, and post-login verification.
- [x] Implement `BetterAuth::Plugins.captcha` with Cloudflare Turnstile, Google reCAPTCHA, hCaptcha, and CaptchaFox provider verification.
- [x] Implement `BetterAuth::Plugins.have_i_been_pwned` with SHA-1 k-anonymity password checks on configured password routes.
- [x] Implement `BetterAuth::Plugins.api_key` with key CRUD, hashing, verification, rate limits, quotas, metadata, secondary storage, and API-key session behavior.
- [x] Add matching Minitest coverage in `packages/better_auth/test/better_auth/plugins/`.
- [x] Add feature docs for each plugin under `.docs/features/`.
- [x] Update `.docs/features/upstream-parity-matrix.md`.
- [x] Update Phase 9 checkboxes in `.docs/plans/2026-04-25-better-auth-ruby-port.md`.

## Verification

- [x] Run each new plugin test individually.
- [x] Run related route and session tests after each plugin.
- [x] Run StandardRB on Phase 9 files and touched core files.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec rake test`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec standardrb`.

Notes:

- Full `rake test` passed outside the sandbox on 2026-04-26 after the sandbox blocked localhost PostgreSQL access: `273 runs, 1377 assertions, 0 failures, 0 errors, 2 skips`.
- Full `standardrb` passed on 2026-04-26.
