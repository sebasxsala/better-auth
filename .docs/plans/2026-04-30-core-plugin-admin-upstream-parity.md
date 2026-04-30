# Admin Plugin Upstream Parity Child Plan

**Parent:** `.docs/plans/2026-04-30-core-plugins-upstream-parity.md`

**Upstream source:** `upstream/packages/better-auth/src/plugins/admin/admin.test.ts`

**Ruby target:** `packages/better_auth/test/better_auth/plugins/admin_test.rb`

## Status

- [x] Extracted upstream server-applicable test titles from Better Auth v1.6.9.
- [x] Mapped upstream titles to Ruby Minitest coverage.
- [x] Documented Ruby exclusions.
- [x] Strengthened Ruby coverage for the previously broad parity buckets.
- [x] Ran focused Ruby test file and targeted lint.

## Coverage Matrix

| Upstream title group | Ruby coverage | Status | Notes |
| --- | --- | --- | --- |
| Get user, create user, create without password, create with multiple roles, server-side create user | `test_admin_manages_users_roles_bans_sessions_and_passwords`, `test_admin_create_user_matches_upstream_validation_and_server_call` | Covered by existing Ruby test | Ruby uses direct API calls and in-memory adapter records. |
| Non-admin authorization failures for get/create/list/update/delete/session/password operations | `test_blocks_non_admin_and_checks_permissions` | Covered by Ruby test | Permission checks are asserted across the admin endpoints with real sessions, no mocks. |
| List users, count, search, pagination, sort, role/id filters, combined filters, `me` shape | `test_admin_list_users_filters_before_pagination_and_reports_total`, `test_admin_list_users_supports_upstream_search_filter_sort_and_shape` | Covered by Ruby test | Includes upstream response shape, `role != user` filtering, and filtering-before-pagination behavior. |
| Set role, multiple roles, invalid configured roles, role updates through update user | `test_admin_manages_users_roles_bans_sessions_and_passwords`, `test_admin_update_user_requires_set_role_permission_for_role_changes`, `test_admin_allows_arbitrary_roles_unless_roles_are_configured`, `test_admin_set_password_edges_and_config_role_validation` | Covered by Ruby test | Type-level custom-role assertions are excluded below. Runtime invalid-role checks cover create user, set role, and update user. |
| Ban, unban, custom ban message, ban expiry, password and social sign-in ban behavior | `test_admin_manages_users_roles_bans_sessions_and_passwords`, `test_admin_ban_hooks_cover_custom_message_expiry_and_social_callback`, `test_admin_get_update_and_ban_shapes_match_upstream` | Covered by existing Ruby test | Social callback is exercised through the core callback path. |
| List, revoke one, and revoke all user sessions | `test_admin_manages_users_roles_bans_sessions_and_passwords`, `test_admin_sessions_and_destructive_endpoints_match_upstream_shapes` | Covered by existing Ruby test | Includes response shape assertions. |
| Impersonation, stop impersonating, admin impersonation permissions, legacy option, hidden impersonated sessions | `test_admin_impersonation_blocks_admins_and_hides_impersonated_sessions`, `test_admin_impersonation_allows_admins_with_impersonate_admins_permission` | Covered by existing Ruby test | Covers current permission and legacy configuration behavior. |
| Set user password validation: empty user id, empty/short/long password, non-admin | `test_admin_set_password_edges_and_config_role_validation` | Covered by existing Ruby test | Uses real password sign-in after update. |
| Update user, delete user, get/update/ban response shapes | `test_admin_get_update_and_ban_shapes_match_upstream`, `test_admin_sessions_and_destructive_endpoints_match_upstream_shapes` | Covered by existing Ruby test | Ruby verifies API payload shape, not TS client types. |
| Access control: validate by user id, role, role priority, banned user with role, missing/empty/NaN user ids | `test_admin_has_permission_requires_user_id_or_role_and_handles_missing_users`, `test_admin_has_permission_matches_upstream_role_priority_and_banned_user`, `test_blocks_non_admin_and_checks_permissions` | Covered by Ruby test | Covers Ruby-equivalent error and boolean outcomes. |
| Client-side validation and TypeScript custom role typing | N/A | Ruby exclusion documented | No Ruby runtime behavior; core gem has no TS client. |

## Verification

- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/admin_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec standardrb --cache false test/better_auth/plugins/admin_test.rb`
