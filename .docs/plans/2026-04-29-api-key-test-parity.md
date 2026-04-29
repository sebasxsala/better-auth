# API Key Upstream Test Parity Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the missing applicable upstream `@better-auth/api-key` tests to the Ruby `better_auth-api-key` package before changing implementation.

**Architecture:** Keep the public API unchanged and expand `packages/better_auth-api-key/test/better_auth/api_key_test.rb` with 1:1 traceable translations from upstream tests. Treat failures from the translated tests as implementation gaps only after the test translation is complete.

**Tech Stack:** Ruby, Minitest, BetterAuth Ruby core, upstream Better Auth `v1.6.9` API key package tests.

---

## Task 1: Translate Missing Upstream Tests

**Files:**
- Modify: `packages/better_auth-api-key/test/better_auth/api_key_test.rb`
- Reference: `upstream/packages/api-key/src/api-key.test.ts`
- Reference: `upstream/packages/api-key/src/org-api-key.test.ts`

- [x] Add 1:1 Ruby tests for create/auth/config parity:
  - `test_create_without_session_or_user_id_returns_unauthorized`
  - `test_create_defaults_rate_limit_enabled_true_when_omitted`
  - `test_create_sets_custom_expires_at_from_expires_in`
  - `test_create_rejects_custom_expires_in_when_custom_expiration_is_disabled`
  - `test_create_accepts_server_side_custom_rate_limit_fields`
- [x] Add 1:1 Ruby tests for verify/rate/usage parity:
  - `test_verify_default_rate_limit_allows_first_ten_and_limits_afterward`
  - `test_verify_allows_requests_after_rate_limit_window_passes`
  - `test_verify_decrements_remaining_count_on_each_successful_use`
- [x] Add 1:1 Ruby tests for update/delete parity:
  - `test_update_rejects_custom_expires_in_when_custom_expiration_is_disabled`
  - `test_update_rejects_expires_in_below_minimum`
  - `test_update_rejects_expires_in_above_maximum`
  - `test_delete_without_session_or_user_id_returns_unauthorized`
- [x] Add 1:1 Ruby tests for list/pagination parity:
  - `test_list_pagination_pages_do_not_overlap`
  - `test_list_sorts_by_created_at_descending`
  - `test_list_combines_created_at_sorting_with_pagination`
- [x] Add 1:1 Ruby tests for secondary storage/fallback parity:
  - `test_secondary_storage_expired_key_returns_key_expired`
  - `test_secondary_storage_reference_list_removes_deleted_key`
  - `test_secondary_storage_fallback_reads_cache_before_database`
  - `test_secondary_storage_fallback_verify_persists_quota_updates_to_database`
  - `test_secondary_storage_fallback_list_populates_all_cache_keys_from_database`
  - `test_secondary_storage_fallback_population_touches_ref_list_once`
  - `test_secondary_storage_pure_mode_does_not_write_database`
  - `test_secondary_storage_fallback_create_writes_database_and_cache`
  - `test_secondary_storage_fallback_update_writes_database_and_cache`
  - `test_secondary_storage_fallback_delete_removes_database_and_cache`
- [x] Add 1:1 Ruby tests for deferred updates:
  - `test_defer_updates_still_enforces_rate_limits`
  - `test_defer_updates_persists_remaining_count_after_background_task`
  - `test_defer_updates_without_background_handler_runs_synchronously`
- [x] Add 1:1 Ruby tests for metadata migration:
  - `test_list_api_keys_migrates_double_stringified_metadata`
  - `test_update_api_key_migrates_double_stringified_metadata`
  - `test_metadata_migration_leaves_properly_formatted_metadata_unchanged`
  - `test_metadata_migration_handles_null_metadata`
- [x] Add 1:1 Ruby tests for organization-owned keys:
  - `test_org_key_create_requires_organization_id`
  - `test_list_without_organization_id_returns_only_user_owned_keys`
  - `test_list_with_organization_id_returns_only_org_owned_keys`
  - `test_list_org_keys_filters_by_config_id`
  - `test_org_owned_key_cannot_create_api_key_session`
  - `test_user_owned_key_can_create_api_key_session_with_org_plugin_installed`
  - `test_mixed_user_and_org_keys_verify_in_same_instance`
  - `test_get_org_owned_key_by_id_from_server`
  - `test_delete_org_owned_key_then_verify_fails`
  - `test_update_org_owned_key_name_and_enabled_status`
- [x] Add 1:1 Ruby tests for organization permission parity:
  - `test_org_non_member_is_denied_full_api_key_crud`
  - `test_org_default_member_without_api_key_permissions_is_denied`
  - `test_org_read_only_member_can_read_but_cannot_create_update_or_delete`
  - `test_org_restricted_member_is_denied_full_api_key_crud`

## Task 2: Verify And Fix Minimal Gaps

**Files:**
- Modify only if needed: `packages/better_auth-api-key/lib/better_auth/plugins/api_key.rb`
- Test: `packages/better_auth-api-key/test/better_auth/api_key_test.rb`

- [x] Run `cd packages/better_auth-api-key && bundle exec ruby -Itest test/better_auth/api_key_test.rb`
- [x] If translated tests fail, fix only the minimal implementation gap needed for upstream parity.
- [x] Re-run `cd packages/better_auth-api-key && bundle exec ruby -Itest test/better_auth/api_key_test.rb`
- [x] If implementation changed, run `cd packages/better_auth-api-key && bundle exec standardrb`

## Assumptions

- Scope is only `packages/better_auth-api-key`; do not edit Rails or browser/client packages.
- Upstream client-only wrapper tests are intentionally excluded, but equivalent server route behavior is included where applicable.
- Tests use Ruby `snake_case` options and upstream-compatible `camelCase` request/response fields, matching the existing package convention.
