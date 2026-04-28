# Plugin Parity: Generic OAuth, HIBP, JWT

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Ruby `generic_oauth`, `have_i_been_pwned`, and `jwt` plugins closer to upstream Better Auth behavior.

**Architecture:** Keep changes inside the framework-agnostic `packages/better_auth` gem. Port upstream behavior from `upstream/packages/better-auth/src/plugins/**` with Ruby-specific compatibility shims where existing persisted data or test hooks already exist.

**Tech Stack:** Ruby, Rack, Minitest, OpenSSL, ruby-jwt.

---

## Tasks

- [x] Add focused parity tests for `generic_oauth` covering PKCE S256, conditional `code_verifier`, missing state, protected state fields, discovery headers, and `override_user_info`.
- [x] Update `packages/better_auth/lib/better_auth/plugins/generic_oauth.rb` to satisfy the new parity tests without breaking existing OAuth/account-cookie behavior.
- [x] Add focused parity tests for `have_i_been_pwned` covering `enabled: false`, kebab-case plugin id, reset-password validation order, and custom lookup behavior.
- [x] Move HIBP checking to the password hashing path so it runs only when a password is actually hashed, while preserving the Ruby-only `range_lookup` testing hook.
- [x] Add focused parity tests for `jwt` covering `jwks_path`, disabled header setting, `define_payload`, `get_subject`, default issuer/audience verification, required `sub`/`aud`, and private-key encryption fallback.
- [x] Update `packages/better_auth/lib/better_auth/plugins/jwt.rb` to align verification defaults, key handling, and option support with upstream, retaining legacy PEM compatibility.
- [ ] Run the complete core suite cleanly; focused plugin tests pass, but full suite is currently blocked by sandboxed DB/socket checks and unrelated dirty-worktree failures.

## Notes

- The plan file named in `AGENTS.md`, `.docs/plans/2026-04-25-better-auth-ruby-port.md`, is absent in this checkout.
- Ruby extensions such as HIBP `range_lookup` and remote JWKS fetching should remain only if covered by tests and documented as Ruby adaptations.
