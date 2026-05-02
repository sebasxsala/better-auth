# SCIM Upstream Parity Gaps Implementation Plan

> **For agentic workers:** Track progress with checkbox steps. Update this plan when a phase completes, when upstream differs materially from the Ruby implementation, or when a Ruby-specific adaptation is chosen.

**Goal:** Close SCIM parity gaps against upstream Better Auth `upstream/packages/scim` at target `v1.6.9`, with special focus on missing case-by-case tests in `packages/better_auth-scim`.

**Architecture:** Keep the Ruby package boundary in `packages/better_auth-scim` and preserve the existing upstream-shaped modules (`routes`, `middlewares`, `mappings`, `patch_operations`, `scim_tokens`, `scim_filters`, `scim_resources`, `user_schemas`). Add missing tests first, then change runtime only where a new parity test exposes a real upstream behavior difference.

**Tech Stack:** Ruby 3.2+, Minitest, Better Auth Ruby memory adapter, upstream TypeScript/Vitest tests as the source of truth.

---

## Source Files Reviewed

- Upstream source: `upstream/packages/scim/src/routes.ts`, `middlewares.ts`, `mappings.ts`, `patch-operations.ts`, `scim-filters.ts`, `scim-resources.ts`, `scim-tokens.ts`, `user-schemas.ts`
- Upstream tests: `upstream/packages/scim/src/scim.test.ts`, `scim-users.test.ts`, `scim-patch.test.ts`, `scim.management.test.ts`
- Ruby source: `packages/better_auth-scim/lib/better_auth/scim/**/*.rb`
- Ruby tests: `packages/better_auth-scim/test/better_auth/scim/*.rb`

## Current Assessment

Runtime behavior appears close to upstream for the shipped SCIM surface: metadata endpoints, bearer token middleware, default and stored token modes, user provisioning, provider scoping, organization scoping, PATCH, and provider management all have Ruby equivalents.

Test parity is lower because the Ruby suite intentionally groups many upstream `it(...)` cases into broader Minitest methods. The remaining work is mostly to add literal parity tests and only then fix behavior if a literal upstream case fails.

## Meaningful Differences Observed

- [x] **Endpoint structure:** Ruby exposes upstream SCIM routes and hides SCIM resource endpoints from OpenAPI, matching upstream hidden metadata intent.
- [x] **SCIM token envelope:** Ruby uses upstream-compatible `base64url(baseToken:providerId[:organizationId])` envelopes.
- [x] **Token storage:** Ruby covers plain, hashed, encrypted, custom hash, and custom encryption/decryption.
- [x] **Provider management:** Ruby supports owner-scoped personal providers, org-scoped providers, required roles, custom creator role, before/after token hooks, and deletion invalidation.
- [x] **Filters:** Ruby matches upstream server behavior for `userName eq` and rejects unsupported operators/attributes. Note: `.docs/features/scim.md` currently says `externalId eq` is supported, but upstream `SCIMUserAttributes` only maps `userName`; Ruby also rejects `externalId`.
- [x] **SCIM resources:** Ruby resource shape matches upstream for exposed user fields: `id`, `externalId`, `meta`, `userName`, `name.formatted`, `displayName`, `active`, `emails`, and `schemas`.
- [x] **Create/update email casing:** Upstream lowercases `userName` through `APIUserSchema`, but does not explicitly lowercase `emails[].value`; Ruby lowercases the selected email in create/update. Ruby keeps this as an intentional SCIM canonicalization adaptation and now has a characterization test.
- [x] **SCIM-created user verification flag:** Ruby creates new SCIM users with `emailVerified: true`; upstream `createUser()` in SCIM does not pass `emailVerified`. Ruby keeps this as an intentional provisioning adaptation and now has a characterization test.
- [x] **PATCH invalid-op error envelope:** Upstream invalid operations are rejected by request validation with a `VALIDATION_ERROR` body. Ruby now returns a matching validation-style error body for invalid PATCH operations.
- [x] **Metadata snapshots:** Ruby now has full metadata/schema/resource type snapshot-style assertions.

## Upstream Test Parity Matrix

### `scim.test.ts`

| Upstream case | Ruby status | Ruby coverage / gap |
| --- | --- | --- |
| ServiceProviderConfig snapshot | Covered | `test_scim_metadata_endpoints_match_upstream_snapshots` asserts the full upstream response shape. |
| Schemas list snapshot | Covered | `test_scim_metadata_endpoints_match_upstream_snapshots` asserts the full User schema attributes/sub-attributes. |
| Single schema snapshot | Covered | `test_scim_metadata_endpoints_match_upstream_snapshots` asserts full schema fields and absolute `meta.location`. |
| Unsupported schema 404 SCIM error | Covered | Same metadata test covers status and schema error envelope. |
| ResourceTypes list snapshot | Covered | `test_scim_metadata_endpoints_match_upstream_snapshots` asserts the full list response. |
| Single ResourceType snapshot | Covered | `test_scim_metadata_endpoints_match_upstream_snapshots` asserts the full resource type response. |
| Unsupported ResourceType 404 SCIM error | Covered | Same metadata test covers status and SCIM error schema. |
| Create new user with 201 + Location | Covered | `test_scim_create_user_sets_location_and_accepts_scim_json`. |
| Create account linked to existing user | Covered | `test_scim_create_user_email_selection_duplicate_and_existing_user`. |
| Create user with external id | Covered grouped | Covered by CRUD test and create grouping. |
| Create user with name parts | Covered grouped | Covered by CRUD test. |
| Create user with formatted name | Covered grouped | Covered by create/update tests. |
| Create user with primary email | Covered | Explicit in create grouping. |
| Create user with first non-primary email | Covered | Explicit in create grouping. |
| Duplicate computed username | Covered | Duplicate create raises `APIError`. |
| Anonymous create rejected | Covered | `test_scim_errors_use_scim_error_shape`. |
| PUT update existing resource | Covered | `test_scim_user_crud_filter_patch_and_delete`. |
| Anonymous PUT rejected | Covered | `test_scim_update_and_patch_reject_anonymous_and_missing_users`. |
| PUT missing user 404 | Covered | Same test. |

### `scim-users.test.ts`

| Upstream case | Ruby status | Ruby coverage / gap |
| --- | --- | --- |
| List two provisioned users | Covered | `test_scim_list_users_returns_upstream_list_response_shape_and_order` asserts two-user response shape and order. |
| Empty list with no users / other org | Covered grouped | `test_scim_org_scoping_empty_lists_and_missing_or_anonymous_access`. |
| List only same provider | Covered | `test_scim_scopes_user_access_by_provider_and_deletes_users`. |
| List only same provider and org | Covered | Org scoping test covers provider/org list separation. |
| Filter list by `userName eq`, case-insensitive | Covered | `test_scim_filters_only_user_name_and_rejects_unsupported_filters`. |
| Anonymous list rejected | Covered | Org scoping test checks 401 response. |
| Get single user | Covered | CRUD test fetches created user. |
| Get only same provider | Covered | Provider scoping test checks cross-provider 404. |
| Get only same provider and org | Covered | `test_scim_org_scoped_get_only_allows_same_provider_and_organization` covers cross-org get 404 parity. |
| Get missing user 404 | Covered | Org scoping test. |
| Anonymous get rejected | Covered | Org scoping test checks 401 response. |
| Delete existing user | Covered | CRUD/delete tests. |
| Anonymous delete rejected | Covered | Org scoping test checks 401 response. |
| Delete missing user 404 | Covered | Org scoping test. |
| Default SCIM provider full CRUD | Covered | `test_scim_default_provider_and_invalid_tokens`. |
| Invalid SCIM token rejected | Covered | Same test. |

### `scim-patch.test.ts`

| Upstream case | Ruby status | Ruby coverage / gap |
| --- | --- | --- |
| Replace partially updates user | Covered grouped | `test_scim_patch_matches_upstream_supported_operations`. |
| Add partially updates user | Covered grouped | Same test mixes add/replace; literal per-op assertion missing. |
| Mixed add/replace operations | Covered | Same test. |
| Multiple name sub-attributes with replace | Covered | `test_scim_patch_supports_upstream_name_subattributes_and_nested_path_variants` covers replace. |
| Multiple name sub-attributes with add | Covered | `test_scim_patch_supports_upstream_name_subattributes_and_nested_path_variants` covers add. |
| Nested object values with path prefix, replace | Covered | `test_scim_patch_supports_upstream_name_subattributes_and_nested_path_variants` covers replace. |
| Nested object values with path prefix, add | Covered | `test_scim_patch_supports_upstream_name_subattributes_and_nested_path_variants` covers add. |
| Operation without explicit path, replace | Covered | `test_scim_patch_supports_upstream_operations_without_explicit_path` covers replace. |
| Operation without explicit path, add | Covered | `test_scim_patch_supports_upstream_operations_without_explicit_path` covers add. |
| Dot notation in paths | Covered | `test_scim_patch_supports_dot_name_paths_and_rejects_noop_patch`. |
| Case-insensitive replace/add op | Covered grouped | Uppercase `REPLACE` and `ADD` covered in one test. |
| Skip add when value already exists | Covered | Duplicate add covered. |
| Ignore replace on non-existing path | Covered | Unknown path no-op covered. |
| Ignore add on non-existing path | Covered | `test_scim_patch_rejects_add_on_non_existing_path` covers add-specific no-op behavior. |
| Ignore non-existing operation | Covered | Ruby now returns upstream-style `VALIDATION_ERROR` body for invalid PATCH operations. |
| Patch missing user 404 | Covered | `test_scim_update_and_patch_reject_anonymous_and_missing_users`. |
| Empty Operations invalid update | Covered | Same validation test covers no valid fields. |
| Anonymous patch rejected | Covered | Same test checks 401 response. |

### `scim.management.test.ts`

| Upstream case | Ruby status | Ruby coverage / gap |
| --- | --- | --- |
| Generate token requires session | Covered | Provider management roles test checks anonymous 401. |
| Authenticated user not in org rejected | Covered | `test_scim_requires_org_plugin_and_membership_for_org_tokens`. |
| Invalid provider id rejected | Covered | Provider management roles test. |
| Client `authClient.scim.generateToken` | Not applicable | Ruby exposes `plugin.client` metadata in `test_scim_plugin_surface_exposes_version_client_and_hidden_metadata`; upstream JS client runtime has no direct Ruby equivalent. |
| Generate token plain | Covered | `test_generates_plain_hashed_and_custom_scim_tokens`. |
| Generate token hashed | Covered | Same test. |
| Generate token custom hash | Covered | Same test. |
| Generate token encrypted | Covered | `test_scim_tokens_use_upstream_envelope_storage_and_encrypted_modes`. |
| Generate token custom encryption | Covered | Same test. |
| Generate token associated to org | Covered | Org token test. |
| Before token hook can block | Covered | Provider management roles test and regeneration hook test. |
| After token hook sees provider/token | Covered | `test_scim_after_token_generation_hook_receives_stored_provider_and_usable_token`. |
| Deny regenerate personal provider for non-owner | Covered | Provider management roles test. |
| Deny regenerate when provider belongs to another org | Covered | Cross-org regeneration test. |
| List empty when user not in org | Covered | `test_scim_provider_management_returns_empty_list_without_memberships`. |
| List org-scoped providers across orgs | Covered | `test_scim_provider_management_lists_only_accessible_org_scoped_providers`. |
| List owned non-org providers for owner | Covered | Provider management roles test. |
| Get provider details when org member | Covered | Provider management roles test. |
| Get own non-org provider | Covered | Provider management roles test. |
| Deny non-org provider for non-owner | Covered | Provider management roles test. |
| Get 403 for provider in another org | Covered | `test_scim_provider_management_denies_get_and_delete_for_other_org`. |
| Creator removed from org cannot access provider | Covered | `test_scim_provider_management_requires_org_membership_after_creator_removed`. |
| Get unknown provider 404 | Covered | Provider management roles test. |
| Delete org provider and invalidate token | Covered | Cross-org/delete invalidation test. |
| Delete 403 for provider in another org | Covered | `test_scim_provider_management_denies_get_and_delete_for_other_org`. |
| Delete unknown provider 404 | Covered | Provider management roles test. |
| Deny delete non-org provider for non-owner | Covered | `test_scim_provider_management_denies_delete_for_non_owner_personal_provider`. |
| Deny org token generation for regular member | Covered | Role test. |
| Allow org token generation for admin | Covered | Role test. |
| Allow multiple roles containing admin | Covered | Role test. |
| Respect custom `requiredRole` | Covered | Role test. |
| Default to customized creator role | Covered | Role test. |
| Filter org providers by role in list endpoint | Covered | Role test. |

## Tasks

### Task 1: Lock Upstream Reference and Baseline

**Files:**
- Read: `upstream/packages/scim/src/*.ts`
- Read: `upstream/packages/scim/src/*.test.ts`
- Read: `packages/better_auth-scim/lib/better_auth/scim/**/*.rb`
- Read: `packages/better_auth-scim/test/better_auth/scim/*.rb`

- [x] Read root `AGENTS.md`.
- [x] Confirm no package-level `AGENTS.md` exists for `packages/better_auth-scim`.
- [x] Review upstream SCIM source and tests.
- [x] Review Ruby SCIM source and tests.
- [x] Confirm `upstream/` is actually checked out at `v1.6.9` before implementing runtime changes.
- [x] Run the current Ruby SCIM suite as a baseline:

```bash
cd packages/better_auth-scim
rbenv exec bundle exec rake test
```

### Task 2: Add Literal Metadata Snapshot Parity Tests

**Files:**
- Modify: `packages/better_auth-scim/test/better_auth/scim/scim_test.rb`
- Reference: `upstream/packages/scim/src/scim.test.ts`
- Runtime only if tests fail: `packages/better_auth-scim/lib/better_auth/scim/user_schemas.rb`, `routes.rb`

- [x] Add exact assertions for `get_scim_service_provider_config`, including `authenticationSchemes`, `schemas`, `patch`, `bulk`, `filter`, `changePassword`, `sort`, `etag`, and `meta`.
- [x] Add exact assertions for `get_scim_schemas`, including every `User` schema attribute and sub-attribute from upstream.
- [x] Add exact assertions for `get_scim_schema` with absolute `meta.location`.
- [x] Add exact assertions for `get_scim_resource_types` and `get_scim_resource_type`.
- [x] Re-run:

```bash
cd packages/better_auth-scim
rbenv exec bundle exec ruby -Itest test/better_auth/scim/scim_test.rb
```

### Task 3: Add Literal User CRUD and Scope Tests

**Files:**
- Modify: `packages/better_auth-scim/test/better_auth/scim/scim_test.rb`
- Modify: `packages/better_auth-scim/test/better_auth/scim/scim_users_test.rb`
- Runtime only if tests fail: `packages/better_auth-scim/lib/better_auth/scim/routes.rb`, `mappings.rb`, `scim_resources.rb`

- [x] Split grouped create tests into upstream-shaped cases for external id, name parts, formatted name, primary email, first non-primary email, duplicate computed username, and existing-user linking.
- [x] Add literal `GET /scim/v2/Users` test that creates two users and asserts `itemsPerPage`, `totalResults`, `startIndex`, `schemas`, and `Resources` order.
- [x] Add literal `GET /scim/v2/Users/:userId` organization-scoped cross-access test: org A token can fetch org A user; org B token gets upstream-style `User not found`.
- [x] Add characterization test for selected `emails[].value` casing. Ruby keeps lowercasing as an intentional SCIM canonicalization adaptation.
- [x] Add characterization test for `emailVerified` on SCIM-created users. Ruby keeps `emailVerified: true` as an intentional provisioning adaptation.
- [x] Re-run:

```bash
cd packages/better_auth-scim
rbenv exec bundle exec ruby -Itest test/better_auth/scim/scim_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/scim/scim_users_test.rb
```

### Task 4: Add Literal PATCH Parity Tests and Fix Error Shape If Needed

**Files:**
- Modify: `packages/better_auth-scim/test/better_auth/scim/scim_patch_test.rb`
- Runtime if tests fail: `packages/better_auth-scim/lib/better_auth/scim/patch_operations.rb`, `routes.rb`
- Reference: `upstream/packages/scim/src/scim-patch.test.ts`, `patch-operations.ts`

- [x] Add separate replace-only and add-only tests for `/externalId`, `/userName`, and `/name/givenName`.
- [x] Add separate replace-only and add-only tests for multiple name sub-attributes.
- [x] Add separate replace-only and add-only tests for nested object values with `path: "name"`.
- [x] Add separate replace-only and add-only tests for operations without explicit `path`.
- [x] Add add-specific non-existing path test that expects `No valid fields to update`.
- [x] Add literal invalid operation test for `op: "update"` and compare Ruby's error body to upstream's validation error body.
- [x] If required, change Ruby PATCH validation so invalid ops fail with upstream-compatible validation error shape instead of `Invalid SCIM patch operation`.
- [x] Re-run:

```bash
cd packages/better_auth-scim
rbenv exec bundle exec ruby -Itest test/better_auth/scim/scim_patch_test.rb
```

### Task 5: Add Provider Management Literal Parity Tests

**Files:**
- Modify: `packages/better_auth-scim/test/better_auth/scim/scim_management_test.rb`
- Runtime only if tests fail: `packages/better_auth-scim/lib/better_auth/scim/routes.rb`, `scim_tokens.rb`, `middlewares.rb`
- Reference: `upstream/packages/scim/src/scim.management.test.ts`

- [x] Add exact after-hook assertion that `scim_provider.scimToken` is a stored string and the returned token remains usable.
- [x] Add multi-org list test that creates provider-1/provider-2 in org A and provider-3 in org B, then asserts user A sees only provider-1/provider-2 with `id`, `providerId`, and `organizationId`.
- [x] Add explicit note or test explaining Ruby client parity: Ruby exposes `plugin.client` metadata, while upstream's `authClient.scim.generateToken` test has no direct Ruby client runtime equivalent.
- [x] Re-run:

```bash
cd packages/better_auth-scim
rbenv exec bundle exec ruby -Itest test/better_auth/scim/scim_management_test.rb
```

### Task 6: Update Docs and Final Verification

**Files:**
- Modify if needed: `.docs/features/scim.md`
- Modify: this plan
- Test: full `packages/better_auth-scim` suite

- [x] Update `.docs/features/scim.md` to remove or qualify the `externalId eq` filter claim unless runtime support is intentionally added after upstream review.
- [x] Update this plan with any runtime differences discovered while adding literal tests.
- [x] Run the full SCIM package suite:

```bash
cd packages/better_auth-scim
rbenv exec bundle exec rake test
```

- [x] Run style checks if this package is covered by the repo's Ruby style tooling:

```bash
cd packages/better_auth-scim
rbenv exec bundle exec standardrb
```

- [x] Commit as a test/parity change unless runtime behavior changes require `fix:`:

```bash
git add .docs/plans/2026-05-01-0127--scim-upstream-parity-gaps.md .docs/features/scim.md packages/better_auth-scim/test/better_auth/scim packages/better_auth-scim/lib/better_auth/scim
git commit -m "test: add SCIM upstream parity coverage"
```

## Completion Criteria

- [x] Every upstream `it(...)` in `upstream/packages/scim/src/*.test.ts` is either covered by a literal Ruby test, explicitly covered by a grouped Ruby test with a note in this plan, or documented as Ruby-not-applicable.
- [x] Any runtime behavior difference discovered by new literal tests is either aligned with upstream or documented as an intentional Ruby-specific adaptation.
- [x] `.docs/features/scim.md` no longer overstates filter support.
- [x] Full `packages/better_auth-scim` tests pass.
