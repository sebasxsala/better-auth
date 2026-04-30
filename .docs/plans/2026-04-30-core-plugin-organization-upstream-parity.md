# Organization Plugin Upstream Parity Child Plan

**Parent:** `.docs/plans/2026-04-30-core-plugins-upstream-parity.md`

**Upstream sources:**

- `upstream/packages/better-auth/src/plugins/organization/organization.test.ts`
- `upstream/packages/better-auth/src/plugins/organization/team.test.ts`
- `upstream/packages/better-auth/src/plugins/organization/organization-hook.test.ts`
- `upstream/packages/better-auth/src/plugins/organization/routes/crud-access-control.test.ts`
- `upstream/packages/better-auth/src/plugins/organization/routes/crud-members.test.ts`
- `upstream/packages/better-auth/src/plugins/organization/routes/crud-org.test.ts`

**Ruby target:** `packages/better_auth/test/better_auth/plugins/organization_test.rb`

## Status

- [x] Extracted upstream server-applicable test titles from Better Auth v1.6.9.
- [x] Mapped upstream titles to Ruby Minitest coverage.
- [x] Documented Ruby exclusions.
- [x] Ran focused Ruby test file.
- [x] Audited checked coverage against implementation and added missing Ruby-applicable parity cases.

## Coverage Matrix

| Upstream title group | Ruby coverage | Status | Notes |
| --- | --- | --- | --- |
| Schema order, active team fields, organization/team/member/invitation additional fields | `test_additional_fields_and_organization_hooks` | Covered by existing Ruby test | Type inference is excluded below; runtime schema and filtering are covered. |
| Create/list/update/activate/delete organization, slug availability, empty/duplicate validation, server-side create/get | `test_creates_lists_updates_activates_and_deletes_organizations`, `test_create_organization_sets_active_and_supports_internal_user_id` | Covered by existing Ruby test | Includes active organization session mutation. |
| Invitations: multiple roles, duplicate email casing, list invitations for org/user/server, expiration/filtering, invite limits, resend/cancel behavior | `test_invites_accepts_lists_and_updates_members`, `test_invitation_security_edges_and_limits`, `test_multi_team_invitations_join_all_teams` | Covered by existing Ruby test | Uses real invitation records and acceptance flow. |
| Member CRUD: get/list/update/remove/leave, multiple roles, owner protection, membership limits, filters, sort/limit/offset, slug/id variants | `test_invites_accepts_lists_and_updates_members`, `test_teams_and_dynamic_roles`, `test_team_limits_membership_checks_and_active_team_clear` | Covered by existing Ruby test | Ruby condenses route CRUD assertions into integration tests. |
| Permissions and access control success/failure, DB role merge, partial action merge | `test_dynamic_access_control_rejects_invalid_and_assigned_roles`, `test_dynamic_access_control_merges_database_permissions_with_builtin_roles` | Covered by existing Ruby test | Includes assigned-role deletion protections and permission merge behavior. |
| Dynamic access-control CRUD routes: create/list/get/update/delete roles, privilege escalation, cross-organization checks | `test_dynamic_access_control_rejects_invalid_and_assigned_roles`, `test_dynamic_access_control_merges_database_permissions_with_builtin_roles` | Covered by existing Ruby test | High-risk escalation cases are covered with real memberships. |
| Team CRUD: create/list/update/remove, max members, explicit organization id, active team, list team members, direct add/remove member | `test_teams_and_dynamic_roles`, `test_team_limits_membership_checks_and_active_team_clear` | Covered by existing Ruby test | Includes active-team clear behavior after removal. |
| Multi-team invitations and leave/remove cleanup across teams | `test_multi_team_invitations_join_all_teams`, `test_team_limits_membership_checks_and_active_team_clear` | Covered by existing Ruby test | Ruby verifies membership across all invited teams. |
| Organization hooks: create/add member/create team/create invitation before/after hooks and database hook creation | `test_additional_fields_and_organization_hooks`, `test_invokes_organization_hooks` | Covered by existing Ruby test | Ruby hooks are synchronous callables; async-only TS timing is not a separate runtime behavior. |
| `getFullOrganization`: id/slug lookup, null with no active org, forbidden/non-existent errors, invitations, slug precedence, member limits | `test_creates_lists_updates_activates_and_deletes_organizations`, `test_invites_accepts_lists_and_updates_members`, `test_team_limits_membership_checks_and_active_team_clear` | Covered by existing Ruby test | Ruby verifies full organization payloads through the API. |
| Client hooks, `$Infer` type inference, authClient-only list invitation behavior | N/A | Ruby exclusion documented | No Ruby runtime behavior in core gem. |

## Follow-up Corrections

- [x] Added coverage for clearing the active organization with `organizationId: nil`.
- [x] Added coverage for `getFullOrganization` explicit missing-organization errors and `membersLimit`/default membership limit behavior.
- [x] Added coverage for `listMembers` using the active organization when no organization id or slug is passed.
- [x] Added coverage for `getActiveMemberRole` targeting a specific organization member via `userId`.
- [x] Added coverage and implementation for `beforeCreateInvitation`/`afterCreateInvitation`, including custom invitation IDs and returned-false invitation fields.
- [x] Updated organization plugin schema to accept explicit IDs for organization plugin models when hooks supply them.
- [x] Enforced team member capacity during team invitations and invitation acceptance.

## Verification

- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/organization_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/schema_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec standardrb lib/better_auth/plugins/organization.rb lib/better_auth/plugins/organization/schema.rb test/better_auth/plugins/organization_test.rb`
- [x] `cd packages/better_auth && rbenv exec bundle exec rake test`
- [x] `cd packages/better_auth && rbenv exec bundle exec standardrb`
