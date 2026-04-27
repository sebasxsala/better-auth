# Organization Plugin

Status: Complete for Ruby server parity.

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

- Organization schema for `organization`, `member`, `invitation`, session active organization fields, optional `team`/`teamMember`, and optional `organizationRole`, with SQL and Rails migration rendering.
- Core organization routes: create, update, delete, check slug, set active, list, get full organization, and has permission.
- Member and invitation routes: add/remove/update/list members, active member/role, leave, invite, accept/reject/cancel/get/list invitations, and list user invitations.
- Team routes when `teams: { enabled: true }`: create, update, remove, list, set active, list user teams, list team members, add/remove team member.
- Dynamic access-control routes when `dynamic_access_control: { enabled: true }`: create, update, delete, get, and list roles, including invalid-resource rejection and assigned-role deletion protection.
- Default organization roles and statements aligned with upstream: `owner`, `admin`, `member`.
- Comma-separated role storage, matching upstream `parseRoles`.
- Configurable Ruby callables for invitation email and organization hooks: before/after organization creation, member addition, and team creation.
- Additional fields on organization, member, invitation, team, and organizationRole schemas, including `returned: false` output filtering.
- Multi-team invitations store comma-separated team IDs and add the accepting member to every invited team.

## Ruby Adaptations

- Server API methods are exposed as `snake_case` methods on `auth.api`.
- Organization metadata is persisted as JSON text for adapter portability and returned as a Ruby hash.
- The upstream browser client and TypeScript type-inference tests are documented but not directly portable to Ruby.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/organization_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/schema/sql_test.rb

cd ../better_auth-rails
rbenv exec bundle exec rspec spec/better_auth/rails/migration_spec.rb
```
