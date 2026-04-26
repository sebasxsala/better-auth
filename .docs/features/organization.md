# Organization Plugin

Status: Partial port for Phase 10.

Upstream source:

- `upstream/packages/better-auth/src/plugins/organization/`
- `upstream/packages/better-auth/src/plugins/organization/organization.test.ts`
- `upstream/packages/better-auth/src/plugins/organization/organization-hook.test.ts`
- `upstream/packages/better-auth/src/plugins/organization/team.test.ts`
- `upstream/packages/better-auth/src/plugins/organization/routes/*.test.ts`

Ruby implementation:

- `packages/better_auth/lib/better_auth/plugins/organization.rb`
- `packages/better_auth/lib/better_auth/plugins/organization/schema.rb`
- `packages/better_auth/test/better_auth/plugins/organization_test.rb`

## What Is Implemented

- Organization schema for `organization`, `member`, `invitation`, session active organization fields, optional `team`/`teamMember`, and optional `organizationRole`.
- Core organization routes: create, update, delete, check slug, set active, list, get full organization, and has permission.
- Member and invitation routes: add/remove/update/list members, active member/role, leave, invite, accept/reject/cancel/get/list invitations, and list user invitations.
- Team routes when `teams: { enabled: true }`: create, update, remove, list, set active, list user teams, list team members, add/remove team member.
- Dynamic access-control routes when `dynamic_access_control: { enabled: true }`: create, update, delete, get, and list roles.
- Default organization roles and statements aligned with upstream: `owner`, `admin`, `member`.
- Comma-separated role storage, matching upstream `parseRoles`.
- Configurable Ruby callables for invitation email and basic organization hooks.

## Ruby Adaptations

- Server API methods are exposed as `snake_case` methods on `auth.api`.
- Organization metadata is persisted as JSON text for adapter portability and returned as a Ruby hash.
- This phase focuses on memory-adapter behavior. SQL/Rails migration hardening for plugin schemas remains later adapter work.
- The upstream browser client and TypeScript type-inference tests are documented but not directly portable to Ruby.
