# Plugin Parity Gaps Admin Organization Access Additional Fields Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close upstream parity gaps in the Ruby `admin`, `organization`, `access`, and `additional_fields` plugin surfaces.

**Architecture:** Keep these plugins inside `packages/better_auth`, matching upstream `better-auth/plugins/*` package boundaries. Preserve Ruby `snake_case` APIs while aligning HTTP paths, JSON response shapes, validation, permissions, and schema behavior with upstream server runtime semantics.

**Tech Stack:** Ruby 3.2+, Rack 3, Minitest, StandardRB, upstream Better Auth TypeScript under `upstream/packages/better-auth`.

---

## Summary

Four exploratory agents compared Ruby against upstream for `admin`, `organization`, `access`, and `additional-fields`. The basic surfaces exist, but parity gaps remain in additional-field input parsing and session updates, organization security/contract behavior, admin role and impersonation permissions, and malformed access-control requests.

## Implementation Tasks

- [ ] Access control rejects malformed per-resource hashes and keeps documented Ruby connector normalization.
- [ ] Admin aligns role validation, `impersonate-admins`, `set-role` response shape, ban timestamps, and permission fallback behavior.
- [ ] Organization aligns high-risk security and contract gaps for slug checks, create/set-active behavior, invitations, members, teams, dynamic access control, and schema metadata.
- [ ] Additional fields parse declared user/session fields before adapters, refresh user cookies after update, expose `update-session`, and apply session defaults with secondary storage.
- [ ] Ruby tests cover the upstream server-runtime scenarios and document TypeScript/client inference as out of scope.

## Verification

```bash
cd packages/better_auth && bundle exec ruby -Itest test/better_auth/plugins/access_test.rb
cd packages/better_auth && bundle exec ruby -Itest test/better_auth/plugins/admin_test.rb
cd packages/better_auth && bundle exec ruby -Itest test/better_auth/plugins/organization_test.rb
cd packages/better_auth && bundle exec ruby -Itest test/better_auth/plugins/additional_fields_test.rb
cd packages/better_auth && bundle exec rake test
cd packages/better_auth && bundle exec standardrb
```

## Notes

- Upstream exports `admin`, `organization`, and `access` from `packages/better-auth`; no Ruby gem extraction is planned for these plugins.
- Upstream `additional-fields` is a TypeScript client inference plugin. Ruby has no typed browser client, so `inferAdditionalFields` is documented as out of scope while server runtime behavior is ported.
- The master plan path previously referenced by `AGENTS.md` is absent in this checkout; `.docs/plans/2026-04-27-plugin-parity-completion.md` is the active parity context.
