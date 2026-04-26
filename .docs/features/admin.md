# Admin Plugin

Status: Partial port for Phase 10.

Upstream source:

- `upstream/packages/better-auth/src/plugins/admin/`
- `upstream/packages/better-auth/src/plugins/admin/admin.test.ts`

Ruby implementation:

- `packages/better_auth/lib/better_auth/plugins/admin.rb`
- `packages/better_auth/lib/better_auth/plugins/admin/schema.rb`
- `packages/better_auth/test/better_auth/plugins/admin_test.rb`

## What Is Implemented

- Admin schema fields on `user`: `role`, `banned`, `banReason`, `banExpires`.
- Admin schema field on `session`: `impersonatedBy`.
- Default roles and statements aligned with upstream: admin can manage users and sessions; default user has no admin permissions.
- User routes: get, create, update, remove, list, set role, ban, unban, set password, and permission checks.
- Session routes: list user sessions, revoke one session, revoke all user sessions.
- Impersonation routes: impersonate user and stop impersonating.
- Database hooks set default user role and reject banned-user session creation, including expired-ban cleanup.
- `/list-sessions` after-hook hides impersonated sessions.

## Ruby Adaptations

- Admin API methods are exposed as `snake_case` methods on `auth.api`.
- Permission checks accept the same `permission`/`permissions` shapes as upstream, but Ruby tests cover runtime behavior instead of TypeScript inference.
- Banned-user OAuth redirect behavior is wired through session-create context when the route passes endpoint context.
