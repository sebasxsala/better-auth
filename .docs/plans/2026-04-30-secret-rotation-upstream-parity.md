# Secret Rotation Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add upstream-compatible `secrets` / `BETTER_AUTH_SECRETS` rotation support for Ruby core encrypted data.

**Architecture:** Add a focused `BetterAuth::SecretConfig` value object and expose it through configuration/context. Keep `secret` as the current signing secret while encrypted payload helpers accept either a plain string or `SecretConfig`.

**Tech Stack:** Ruby, Minitest, OpenSSL AES-GCM, JWE gem, existing BetterAuth core/plugin APIs.

---

- [x] Add failing config and crypto tests for versioned secrets, envelope encryption, legacy fallback, and rotated JWE decode.
- [x] Implement `BetterAuth::SecretConfig`, configuration parsing/validation, and context exposure.
- [x] Update symmetric encryption and JWE helpers to accept `SecretConfig`.
- [x] Route encrypted-data call sites through `ctx.context.secret_config`; keep signing/HMAC/JWT call sites on `ctx.context.secret`.
- [x] Add integration coverage for session/account cookies, OAuth token encryption, Generic OAuth state, Email OTP, Two Factor, JWT private-key encryption, and OAuth Proxy secret override.
- [x] Document `secrets` and `BETTER_AUTH_SECRETS` in `packages/better_auth/README.md`.
- [x] Run targeted Minitest files, core test suite, and StandardRB.
