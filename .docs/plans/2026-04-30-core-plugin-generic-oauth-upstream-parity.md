# Generic OAuth Plugin Upstream Parity Child Plan

**Parent:** `.docs/plans/2026-04-30-core-plugins-upstream-parity.md`

**Upstream source:** `upstream/packages/better-auth/src/plugins/generic-oauth/generic-oauth.test.ts`

**Ruby target:** `packages/better_auth/test/better_auth/plugins/generic_oauth_test.rb`

## Status

- [x] Extracted upstream server-applicable test titles from Better Auth v1.6.9.
- [x] Mapped upstream titles to Ruby Minitest coverage.
- [x] Documented Ruby exclusions.
- [x] Ran focused Ruby test file.
- [x] Ported remaining upstream social-provider `getUserInfo` shape for generic OAuth and helper factory defaults.
- [x] Re-ran the focused Ruby test file outside the sandbox because the local OAuth test server binds to `127.0.0.1`.

## Coverage Matrix

| Upstream title group | Ruby coverage | Status | Notes |
| --- | --- | --- | --- |
| Provider redirect, callback, new-user callback, linked account callback, custom redirect URI | `test_sign_in_oauth2_generates_authorization_url_with_state_and_scopes`, `test_callback_creates_user_account_session_and_redirects_new_user`, `test_link_account_generates_link_state_and_callback_links_to_current_user` | Covered by existing Ruby test | Uses real state cookies and callback routing. |
| Invalid provider, callback server error, missing state, provider token errors | `test_invalid_provider_and_issuer_mismatch_errors`, `test_callback_without_state_redirects_to_restart_error`, `test_callback_redirects_when_custom_get_token_raises` | Covered by existing Ruby test | Ruby asserts redirect/error outcomes. |
| Disabled sign-up, explicit sign-up request, existing-user reuse, override user info | `test_callback_reuses_existing_user_and_honors_disable_implicit_sign_up`, `test_override_user_info_updates_existing_user_on_sign_in` | Covered by existing Ruby test | Includes no-duplicate-account behavior. |
| Authorization headers, token exchange, PKCE, response mode, dynamic authorization params | `test_pkce_uses_s256_challenge_and_token_exchange_only_sends_verifier_when_enabled`, `test_sign_in_oauth2_supports_dynamic_authorization_params_and_response_mode`, `test_standard_http_token_exchange_supports_headers_basic_auth_params_and_userinfo_mapping` | Covered by existing Ruby test | Local OAuth test server is used for real HTTP exchange. |
| Numeric account IDs, custom `getUserInfo`, `mapProfileToUser`, missing email redirect | `test_callback_handles_numeric_account_ids_without_duplicate_accounts`, `test_callback_applies_map_profile_to_user_callable`, `test_callback_redirects_when_provider_and_mapped_profile_omit_email` | Covered by Ruby tests | Ruby coerces external account ids safely and redirects with `email_is_missing` when no email can be resolved. |
| Cookie-based and database-backed state storage, state mismatch, state cookie clear/delete | `test_state_cookie_is_set_and_cleared_for_database_state_strategy`, `test_cookie_state_strategy_uses_oauth_state_cookie`, `test_cookie_state_strategy_rejects_state_mismatch`, `test_cookie_state_strategy_rejects_missing_state_cookie` | Covered by existing Ruby test | Includes state-cookie path behavior. |
| Provider helper factories: Okta, Auth0, Microsoft Entra ID, Slack, Keycloak and integration defaults | `test_provider_helper_factories_match_upstream_defaults` | Covered by existing Ruby test | Ruby helper factory names follow Ruby conventions while matching server config. |
| Social provider `getUserInfo` contract and `mapProfileToUser` mapping | `test_social_provider_get_user_info_applies_map_profile_to_user_callable` | Covered by new Ruby test | Ruby returns `{user:, data:}` like upstream; mapped custom fields are Ruby-normalized. |
| OIDC discovery helper factories without custom userinfo callbacks | `test_oidc_discovery_provider_helpers_do_not_install_custom_user_info_callbacks` | Covered by new Ruby test | Auth0, Okta, and Keycloak now rely on generic discovery userinfo flow, matching upstream helper defaults. |
| Duplicate provider IDs warnings | `test_duplicate_provider_ids_emit_warning` | Covered by existing Ruby test | Covers one and multiple duplicate ids. |
| RFC 9207 issuer validation and discovery issuer fallback | `test_invalid_provider_and_issuer_mismatch_errors`, `test_discovery_headers_are_sent_when_fetching_metadata` | Covered by existing Ruby test | Includes discovery fetch headers. |
| Custom token methods, GET token endpoints, basic auth, params, userinfo mapping | `test_standard_http_token_exchange_supports_headers_basic_auth_params_and_userinfo_mapping`, `test_callback_redirects_when_custom_get_token_raises` | Covered by existing Ruby test | Local server validates request method and headers. |
| Account info/refresh routes, account cookie, encrypted stored tokens | `test_generic_oauth_provider_is_available_to_account_info`, `test_generic_oauth_provider_refreshes_access_tokens_through_account_routes`, `test_generic_oauth_sets_and_refreshes_account_cookie`, `test_account_routes_can_read_generic_oauth_account_cookie`, `test_generic_oauth_encrypts_stored_tokens_and_returns_decrypted_access_token` | Covered by existing Ruby test | Exercises account route integration, not just plugin unit logic. |
| Type-only assertions and async-specific TS wording | N/A | Ruby exclusion documented | Ruby uses synchronous callables and runtime assertions. |

## Verification

- [x] `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/generic_oauth_test.rb` (`29 runs, 143 assertions`)
- [x] `cd packages/better_auth && rbenv exec bundle exec standardrb lib/better_auth/plugins/generic_oauth.rb test/better_auth/plugins/generic_oauth_test.rb`

Note: this file opens a local TCP server. It fails under the restricted sandbox with `Errno::EPERM` on `127.0.0.1:0`, then passes outside the sandbox.
