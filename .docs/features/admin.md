# Admin Plugin

Status: Complete for Ruby server parity.

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
- User routes: get, create with or without password, update, remove, list, set role, ban, unban, set password, and permission checks.
- `/admin/list-users` delegates search/filter/sort/count/pagination through the adapter, reports the total matching count, supports `contains`/`starts_with`/`ends_with` search, role/banned/id filters, `_id` aliases, falsy filter values, comparison operators, and sorting.
- Role changes through `/admin/update-user`, `/admin/set-role`, and `/admin/create-user` validate configured roles; updating `role` requires `user:set-role` in addition to `user:update`.
- Session routes: list user sessions, revoke one session, revoke all user sessions.
- Destructive routes return upstream-style `{ success: true }` responses.
- Impersonation routes: impersonate user, reject admin impersonation by default, store/restore the original admin session through the signed `admin_session` cookie, and stop impersonating by restoring the original session.
- Database hooks set default user role and reject banned-user session creation, including custom messages, OAuth callback redirects, and expired-ban cleanup.
- `/list-sessions` after-hook hides impersonated sessions.
- `/admin/has-permission` validates `permission`/`permissions`, honors authenticated sessions, supports direct server checks by `userId` or `role`, prioritizes explicit roles for direct checks, and returns upstream-style errors for blank or missing users.

## Ruby Adaptations

- Admin API methods are exposed as `snake_case` methods on `auth.api`.
- Permission checks accept the same `permission`/`permissions` shapes as upstream, but Ruby tests cover runtime behavior instead of TypeScript inference.
- Banned-user OAuth redirect behavior is wired through session-create context when the route passes endpoint context.
- Ruby adapters normalize generated IDs to strings, so upstream's `useNumberId` TypeScript/client edge is covered by accepting/coercing server `userId` inputs rather than exposing a separate numeric-ID mode.
