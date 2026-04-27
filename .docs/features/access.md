# Access Plugin

Status: Complete for Ruby server parity.

Upstream source:

- `upstream/packages/better-auth/src/plugins/access/access.ts`
- `upstream/packages/better-auth/src/plugins/access/access.test.ts`

Ruby implementation:

- `packages/better_auth/lib/better_auth/plugins/access.rb`
- `packages/better_auth/test/better_auth/plugins/access_test.rb`

## What Is Implemented

- `BetterAuth::Plugins.create_access_control(statements)`.
- `AccessControl#new_role` plus upstream-style alias `newRole`.
- `Role#authorize(request, connector = "AND")`.
- Resource-level `AND`/`OR` checks and per-resource action connector checks.
- Upstream error strings for unknown resources, unauthorized resource access, and generic denial.

## Ruby Adaptations

- TypeScript type inference is not applicable in Ruby; runtime behavior is covered instead.
- Public Ruby method names use `snake_case`, with `newRole` kept as a convenience alias for upstream naming.
