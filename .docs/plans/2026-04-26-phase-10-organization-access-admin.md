# Fase 10: Organization, Access y Admin

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` or `subagent-driven-development` to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Port the Better Auth upstream B2B surface into the Ruby core gem: access control, organizations, teams, invitations, dynamic roles, and admin user management.

**Architecture:** Keep all behavior in `packages/better_auth` as Rack/core plugins. The public HTTP paths, option names, schema concepts, role strings, and error messages should follow upstream; Ruby internals should stay idiomatic and dependency-free.

**Tech Stack:** Ruby 3.2+, Rack 3, Minitest, StandardRB, and upstream Better Auth TypeScript as the source of truth.

---

## Upstream References

- Access source: `upstream/packages/better-auth/src/plugins/access/`
- Access tests: `upstream/packages/better-auth/src/plugins/access/access.test.ts`
- Organization source: `upstream/packages/better-auth/src/plugins/organization/`
- Organization tests: `upstream/packages/better-auth/src/plugins/organization/organization.test.ts`, `organization-hook.test.ts`, `team.test.ts`, and `routes/*.test.ts`
- Admin source: `upstream/packages/better-auth/src/plugins/admin/`
- Admin tests: `upstream/packages/better-auth/src/plugins/admin/admin.test.ts`

## Implementation Steps

- [x] Create this phase plan file in `.docs/plans/`.
- [x] Add Ruby access-control tests, verify they fail, then implement `BetterAuth::Plugins.create_access_control`.
- [x] Add Ruby organization tests, verify they fail, then implement organization schema, permission helpers, adapter helpers, and endpoints.
- [x] Add Ruby admin tests, verify they fail, then implement admin schema, permission helpers, hooks, and endpoints.
- [x] Require the new plugins from `packages/better_auth/lib/better_auth.rb`.
- [x] Update `.docs/features/access.md`, `.docs/features/organization.md`, `.docs/features/admin.md`, and the upstream parity matrix.
- [x] Update `.docs/plans/2026-04-25-better-auth-ruby-port.md` phase 10 checkboxes.
- [ ] Run focused plugin tests, the core test suite, and StandardRB.

## Ruby Adaptations

- Ruby exposes server API methods in `snake_case` while preserving upstream route paths.
- Role collections are stored as comma-separated strings, matching upstream `parseRoles`.
- Organization and admin callbacks are Ruby callables.
- No new runtime dependency is introduced for this phase.
