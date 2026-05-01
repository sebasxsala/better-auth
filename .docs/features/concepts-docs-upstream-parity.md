# Concepts Docs Upstream Parity

Source target: Better Auth upstream `v1.6.9`.

This matrix tracks each upstream concept page before rewriting the Ruby docs. Status values:

- `Ruby docs`: directly document the Ruby behavior.
- `Ruby docs with adaptation`: document the upstream behavior with Ruby/Rack/Rails examples or Ruby-specific wording.
- `Implemented first`: add or verify missing Ruby behavior with tests before documenting.
- `Ruby exclusion`: omit or briefly explain because the upstream section is TypeScript, JavaScript client, package-manager, or framework-specific.

## API

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Calling API Endpoints on the Server | Ruby docs with adaptation | `packages/better_auth/lib/better_auth/api.rb`, `packages/better_auth/test/better_auth/api_test.rb` | Use `auth.api.<endpoint>(body:, headers:, query:)` Ruby examples. |
| Body, Headers, Query | Ruby docs with adaptation | `api.rb`, route tests under `packages/better_auth/test/better_auth/routes/` | Show Ruby hashes and Rack cookie header usage. |
| Getting `headers` and Response Object | Ruby docs with adaptation | `api.rb`, `endpoint.rb`, `api_test.rb` | Show `return_headers: true`/`as_response: true` behavior supported by the Ruby API. |
| Error Handling | Ruby docs with adaptation | `packages/better_auth/lib/better_auth/api_error.rb`, route tests | Translate `onError` and thrown API errors to `rescue BetterAuth::APIError`. |

## CLI

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Generate | Ruby docs with adaptation | `packages/better_auth-rails/lib/generators/better_auth/migration/migration_generator.rb`, generator specs | Replace upstream package command with Rails migration generator. |
| Migrate | Ruby docs with adaptation | Rails generated migration, `packages/better_auth-rails/spec/better_auth/rails/migration_spec.rb` | Use Rails migration workflow. |
| Init | Ruby docs with adaptation | `packages/better_auth-rails/lib/generators/better_auth/install/install_generator.rb`, install generator spec | Use `bin/rails generate better_auth:install` and `bin/rails better_auth:init`. |
| Info | Ruby exclusion | No Ruby CLI equivalent | Omit upstream CLI info command; optionally mention Ruby gem commands. |
| Secret | Ruby docs with adaptation | `packages/better_auth/lib/better_auth/secret_config.rb`, Rails README | Use Ruby secret generation/configuration guidance instead of upstream CLI. |
| Common Issues | Ruby docs with adaptation | Rails generator specs, core setup docs | Adapt to Ruby/Rails setup issues. |

## Client

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Installation | Ruby docs with adaptation | `packages/better_auth/README.md`, `packages/better_auth-rails/README.md` | Use Ruby gem installation and Rack/Rails mounting. |
| Create Client Instance | Ruby exclusion | Upstream JS client only | Replace with server-side Ruby API object and HTTP/curl examples. |
| Usage | Ruby docs with adaptation | Core route tests, `api.rb` | Show curl and `auth.api` flows for sign up, sign in, get session, sign out. |
| Hooks | Ruby exclusion | React/Vue/Svelte/Solid client hooks are not part of Ruby port | Omit hook APIs; Rails controller helpers are the Ruby equivalent. |
| Fetch Options | Ruby exclusion | Upstream fetch client only | Document browser HTTP credentials/CORS behavior where relevant. |
| Disabling Default Fetch Plugins | Ruby exclusion | Upstream JS client only | Omit. |
| Session Options | Ruby docs with adaptation | `routes/session.rb`, `session_test.rb`, Rails controller helper spec | Use cookie sessions, `get_session`, and Rails helpers. |
| Handling Errors | Ruby docs with adaptation | `api_error.rb`, route tests | Use `BetterAuth::APIError` and HTTP status handling. |
| Plugins | Ruby docs with adaptation | `plugin.rb`, plugin tests | Point to server plugin configuration and plugin-specific Ruby docs. |

## Cookies

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Cookie Prefix | Ruby docs | `packages/better_auth/lib/better_auth/cookies.rb`, `cookies_test.rb` | Document `advanced.cookie_prefix` and secure prefix behavior. |
| Custom Cookies | Ruby docs | `cookies.rb`, `cookies_test.rb` | Document `advanced.cookies` with Ruby hash examples. |
| Cross Subdomain Cookies | Ruby docs | `cookies.rb`, `auth_context_upstream_parity_test.rb` | Document `advanced.cross_subdomain_cookies`. |
| Secure Cookies | Ruby docs | `cookies.rb`, configuration tests | Document `advanced.use_secure_cookies` and default attributes. |
| Safari, ITP, and Cross-Domain Setups | Ruby docs with adaptation | Cookie configuration docs | Keep upstream guidance, adapt examples to Rack/Rails deployment. |
| Reverse Proxy Examples | Ruby docs with adaptation | Deployment/docs-only | Keep concept guidance; use Ruby-neutral proxy examples. |
| Shared Parent Domain | Ruby docs | `cookies.rb`, `auth_context_upstream_parity_test.rb` | Keep Ruby configuration example. |

## Database

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Adapters | Ruby docs | `packages/better_auth/lib/better_auth/adapters/`, adapter tests | Document Memory, SQLite, Postgres, MySQL, MSSQL, Mongo shim, Rails ActiveRecord. |
| CLI | Ruby docs with adaptation | Rails generators, migration specs | Replace upstream CLI with Rails generator and core SQL schema APIs. |
| Programmatic Migrations | Ruby docs with adaptation | `schema/sql.rb`, `schema/sql_test.rb` | Show Ruby schema generation, not Kysely/TypeScript. |
| Secondary Storage | Ruby docs | `adapters/internal_adapter.rb`, `internal_adapter_test.rb`, `session_routes_test.rb` | Document Ruby storage contract: `get`, `set`, `delete`, TTL. |
| Redis Storage | Ruby docs with adaptation | `packages/better_auth-redis-storage/README.md` | Link/use Ruby Redis storage package if present. |
| Core Schema: User | Ruby docs | `schema.rb`, `schema_test.rb` | Document Ruby logical fields and custom field names. |
| Core Schema: Session | Ruby docs | `schema.rb`, session tests | Document session fields and additional session fields. |
| Core Schema: Account | Ruby docs | `schema.rb`, account tests | Document account fields and OAuth token storage. |
| Core Schema: Verification | Ruby docs | `schema.rb`, internal adapter tests | Document verification table/storage. |
| Custom Tables | Ruby docs | `schema.rb`, `schema/sql_test.rb` | Document `model_name` and field overrides. |
| Extending Core Schema | Ruby docs | `schema.rb`, route tests for additional fields | Use `additional_fields`. |
| ID Generation | Ruby docs | `configuration.rb`, `internal_adapter_test.rb`, `schema/sql_test.rb` | Document `advanced.database.generate_id`/Ruby equivalent options after verifying names. |
| Numeric IDs, UUIDs, Mixed ID Types | Ruby docs with adaptation | schema/internal adapter tests | Document only supported Ruby ID behavior. |
| Database Hooks | Ruby docs | `database_hooks.rb`, `internal_adapter_test.rb`, `user_routes_test.rb` | Use Ruby lambda examples. |
| Plugins Schema | Ruby docs | plugin schema tests | Show plugin schema registration. |
| Experimental Joins | Ruby exclusion | Upstream experimental TypeScript adapter behavior | Omit unless Ruby adds an equivalent. |

## Email

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Adding Email Verification to Your App | Ruby docs | `routes/email_verification.rb`, `email_verification_test.rb` | Use `email_verification: { send_verification_email: ->(data, request) { ... } }`. |
| Triggering Email Verification: During Sign-up | Ruby docs | `routes/sign_up.rb`, `sign_up_test.rb` | Document `send_on_sign_up: true`; mention default when `require_email_verification` is true. |
| Triggering Email Verification: Require Email Verification | Ruby docs | `routes/sign_in.rb`, `sign_in_test.rb` | Document `email_and_password.require_email_verification` and `send_on_sign_in`. |
| Triggering Email Verification: Manually | Ruby docs | `routes/email_verification.rb`, `email_verification_test.rb` | Use `auth.api.send_verification_email`. |
| Verifying the Email | Ruby docs | `routes/email_verification.rb`, `email_verification_test.rb` | Use `auth.api.verify_email(query: { token: ... })` and link callback behavior. |
| Auto Sign In After Verification | Ruby docs | `routes/email_verification.rb`, `email_verification_test.rb` | Document `auto_sign_in_after_verification`. |
| Callback before email verification | Ruby docs | `routes/email_verification.rb`, `email_verification_test.rb` | Document `before_email_verification`. |
| Callback after successful email verification | Ruby docs | `routes/email_verification.rb`, `email_verification_test.rb` | Document `after_email_verification` and `on_email_verification` Ruby alias behavior. |
| Callback on duplicate sign-up attempt | Ruby docs | `routes/sign_up.rb`, `sign_up_test.rb` | Document `on_existing_user_sign_up`. |
| Password Reset Email | Ruby docs | `routes/password.rb`, `password_test.rb` | Document `send_reset_password`, reset token flow, and revocation option. |

## Hooks

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Before Hooks | Ruby docs | `router.rb`, `auth_context_upstream_parity_test.rb` | Use `hooks: { before: [...] }` Ruby examples. |
| Modify Request Context | Ruby docs | `endpoint.rb`, router/API tests | Document `ctx.merge_context!`. |
| After Hooks | Ruby docs | `router.rb`, `auth_context_upstream_parity_test.rb` | Use after hook examples for response decoration. |
| Ctx > Request Response | Ruby docs | `endpoint.rb`, `auth_context_upstream_parity_test.rb` | Document `ctx.json`, `ctx.redirect`, `ctx.set_cookie`, `ctx.error`. |
| Ctx > Context | Ruby docs | `context.rb`, configuration tests | Document `ctx.context` fields that Ruby exposes. |
| New Session, Returned, Response Headers, Predefined Auth Cookies | Ruby docs | `context.rb`, `endpoint.rb`, plugin tests | Use Ruby context names. |
| Secret, Password, Adapter, Internal Adapter, generateId | Ruby docs with adaptation | `context.rb`, `configuration.rb`, `schema.rb` | Use Ruby helper names and note exact support. |
| runInBackground, runInBackgroundOrAwait | Ruby docs with adaptation | `context.rb` | Document `ctx.context.run_in_background`; omit `runInBackgroundOrAwait` if no distinct Ruby API exists. |
| Reusable Hooks | Ruby docs with adaptation | Hook config/tests | Show Ruby helper lambdas. |

## OAuth

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Configuring Social Providers | Ruby docs | `social_providers/`, `social_providers_test.rb` | Use `BetterAuth::SocialProviders.github(...)` style examples. |
| Sign In | Ruby docs | `routes/social.rb`, `social_test.rb` | Document `auth.api.sign_in_social`. |
| Link account | Ruby docs | `routes/social.rb`, `routes/account.rb`, social/account tests | Document `link_social` and ID-token/native linking where supported. |
| Get Access Token | Ruby docs | `routes/account.rb`, `account_test.rb`, social tests | Document `get_access_token` and `refresh_token`. |
| Get Account Info Provided by the provider | Ruby docs | `routes/account.rb`, `account_test.rb` | Document `account_info`. |
| Requesting Additional Scopes | Ruby docs with adaptation | provider configuration/tests | Use provider `scopes`/`scope` Ruby options after verification. |
| Passing Additional Data Through OAuth Flow | Ruby docs with adaptation | `routes/social.rb`, social tests | Document only if Ruby state data support is verified. |
| Accessing Additional Data in Hooks | Ruby docs with adaptation | hooks/social tests | Document only supported hook data. |
| Handling Providers Without Email | Ruby docs with adaptation | provider profile mapping tests | Use `map_profile_to_user` if supported. |
| Provider Options | Ruby docs with adaptation | social provider classes/tests | Document supported Ruby provider options; exclude unsupported JS-only callbacks. |
| refreshAccessToken, getUserInfo, mapProfileToUser | Ruby docs | social provider classes, `routes/account.rb`, tests | Translate to `refresh_access_token`, `get_user_info`, `map_profile_to_user`. |

## Plugins

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Using a Plugin | Ruby docs | `plugins.rb`, plugin tests | Use `BetterAuth::Plugins.*` examples. |
| Creating a Plugin | Ruby docs with adaptation | `plugin.rb`, `plugin_test.rb` | Show Ruby `BetterAuth::Plugin.new`. |
| Server Plugin: Endpoints | Ruby docs | `endpoint.rb`, `plugin_test.rb` | Show endpoint definitions. |
| Server Plugin: Schema | Ruby docs | `schema.rb`, plugin schema tests | Show plugin schema hash. |
| Server Plugin: Hooks | Ruby docs | `router.rb`, `plugin_test.rb` | Show before/after hooks. |
| Server Plugin: Middleware | Ruby docs | `router.rb`, `plugin_test.rb` | Show middleware lambdas. |
| On Request & On Response | Ruby docs | `router.rb`, `plugin_test.rb` | Show `on_request` and `on_response`. |
| Rate Limit | Ruby docs | `plugin.rb`, `rate_limiter.rb`, router tests | Show plugin `rate_limit`. |
| Trusted origins | Ruby docs | `context.rb`, `auth_context_upstream_parity_test.rb` | Show plugin init merging trusted origins. |
| Server-plugin helper functions | Ruby docs with adaptation | `routes/session.rb`, `context.rb`, plugin tests | Use Ruby equivalents: `Routes.current_session`, endpoint middleware, direct checks. |
| Creating a client plugin | Ruby exclusion | Upstream JS client only | Omit. |
| Endpoint Interface, Get actions, Get Atoms, Path methods, Fetch plugins, Atom Listeners | Ruby exclusion | Upstream JS client only | Omit. |

## Rate Limit

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Default rate limit config examples | Ruby docs | `configuration.rb`, `rate_limiter.rb`, router tests | Document default and special auth path rules. |
| Connecting IP Address | Ruby docs | `request_ip.rb`, router tests | Use `advanced.ip_address.ip_address_headers`. |
| IPv6 Address Support | Ruby docs with adaptation | `request_ip.rb`, router tests | Verify and document actual Ruby behavior. |
| IPv6 Subnet Rate Limiting | Ruby docs | `request_ip.rb`, `request_ip_test.rb`, `router_test.rb` | Document `advanced.ip_address.ipv6_subnet`; note Ruby follows upstream implementation/tests for default subnet behavior. |
| Rate Limit Window | Ruby docs | `rate_limiter.rb`, router tests | Document `window`, `max`, custom rules. |
| Storage | Ruby docs | `rate_limiter.rb`, `router_test.rb`, `schema.rb` | Document memory, custom, secondary-storage, and database storage. |
| Handling Rate Limit Errors | Ruby docs with adaptation | `rate_limiter.rb`, router tests | Use HTTP response and Ruby client error handling; omit JS `onError`. |
| Schema | Ruby docs | `schema.rb`, `schema_test.rb`, `router_test.rb` | Document database rate limit schema for `storage: "database"`. |

## Session Management

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Session table | Ruby docs | `schema.rb`, `schema_test.rb` | Document Ruby session fields. |
| Session Expiration | Ruby docs | `session.rb`, `session_test.rb` | Document `expires_in`, `update_age`, `fresh_age`. |
| Disable Session Refresh | Ruby docs | `session.rb`, `session_test.rb` | Document `disableRefresh`/`disable_refresh` query option. |
| Defer Session Refresh | Ruby docs with adaptation | `session.rb`, `configuration.rb` | Document only if Ruby has equivalent behavior; otherwise fold into refresh behavior. |
| Session Freshness | Ruby docs | `routes/session.rb`, `session_test.rb` | Document sensitive endpoints and `fresh_age`. |
| Get Session | Ruby docs | `routes/session.rb`, `session_routes_test.rb` | Use `auth.api.get_session`. |
| Use Session | Ruby docs with adaptation | Rails controller helpers spec | Replace JS hook with Rails helpers/Rack API. |
| List Sessions | Ruby docs | `routes/session.rb`, `session_routes_test.rb` | Use `auth.api.list_sessions`. |
| Revoke Session | Ruby docs | `routes/session.rb`, `session_routes_test.rb` | Use `auth.api.revoke_session`. |
| Revoke Other Sessions | Ruby docs | `routes/session.rb`, `session_routes_test.rb` | Use `auth.api.revoke_other_sessions`. |
| Revoke All Sessions | Ruby docs | `routes/session.rb`, `session_routes_test.rb` | Use `auth.api.revoke_sessions`. |
| Update Session | Ruby docs | `routes/session.rb`, session route tests | Use `auth.api.update_session`. |
| Revoking Sessions on Password Change | Ruby docs | `routes/user.rb`, `user_routes_test.rb` | Document `revoke_other_sessions`. |
| Session Caching: Cookie Cache | Ruby docs | `session.rb`, `cookies.rb`, config tests | Document `session.cookie_cache`. |
| Cookie Cache Strategies | Ruby docs | `cookies.rb`, config tests | Document `compact`/`jwe` only if both are verified. |
| Sessions in Secondary Storage | Ruby docs | `internal_adapter.rb`, internal adapter/session tests | Document `secondary_storage`. |
| Storing Sessions in the Database | Ruby docs | `internal_adapter.rb`, schema tests | Document `store_session_in_database`. |
| Preserving Sessions | Ruby docs | `internal_adapter.rb`, session route tests | Document `preserve_session_in_database`. |
| Stateless Session Management | Ruby docs | `configuration.rb`, `auth_context_upstream_parity_test.rb` | Document stateless setup for `database: nil`. |
| Versioning Stateless Sessions | Ruby docs | `cookies.rb`, tests | Document cookie cache version if supported. |
| Stateless with Secondary Storage | Ruby docs | `configuration.rb`, internal adapter tests | Document supported combined mode. |
| Customizing Session Response | Ruby docs with adaptation | `plugins/custom_session.rb`, additional fields tests | Use Ruby custom session/additional fields patterns. |

## TypeScript

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| TypeScript Config | Ruby exclusion | Not Ruby-applicable | Remove from concepts. |
| Inferring Types | Ruby exclusion | Not Ruby-applicable | Remove from concepts. |
| Additional Fields | Ruby docs with adaptation | `schema.rb`, additional fields tests | Move Ruby-relevant content to database/users/session docs. |
| Inferring Additional Fields on Client | Ruby exclusion | JS client only | Remove. |
| Current local Ruby Port Notes | Ruby docs with adaptation | Existing docs content | Move useful notes into `api`, `basic-usage`, or Rails integration before deleting/renaming this page. |

## Users And Accounts

| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Update User Information | Ruby docs | `routes/user.rb`, `user_routes_test.rb` | Use `auth.api.update_user`. |
| Change Email | Ruby docs | `routes/user.rb`, `user_routes_test.rb` | Use `auth.api.change_email`. |
| Confirming with Current Email | Ruby docs | `routes/user.rb`, `routes/email_verification.rb`, `email_verification_test.rb` | Document `send_change_email_confirmation` two-step flow. |
| Updating Without Verification | Ruby docs | `routes/user.rb`, `user_routes_test.rb` | Document `update_email_without_verification`. |
| Client Usage | Ruby docs with adaptation | `api.rb`, route tests | Replace JS client with Ruby API/HTTP. |
| Change Password | Ruby docs | `routes/user.rb`, `user_routes_test.rb` | Use `auth.api.change_password`. |
| Set Password | Ruby docs | `routes/user.rb`, `user_routes_test.rb` | Use `auth.api.set_password`. |
| Verify Password | Ruby docs | `routes/password.rb`, `password_test.rb` | Use `auth.api.verify_password`. |
| Delete User | Ruby docs | `routes/user.rb`, `user_routes_test.rb` | Use `auth.api.delete_user` and `delete_user_callback`. |
| Adding Verification Before Deletion | Ruby docs | `routes/user.rb`, `user_routes_test.rb` | Document `send_delete_account_verification`. |
| Authentication Requirements | Ruby docs | `routes/user.rb`, `user_routes_test.rb` | Document password, fresh session, and token flows. |
| Callbacks | Ruby docs | `routes/user.rb`, `user_routes_test.rb` | Document `before_delete`/`after_delete`. |
| List User Accounts | Ruby docs | `routes/account.rb`, `account_test.rb` | Use `auth.api.list_accounts`. |
| Token Encryption | Ruby docs | `routes/account.rb`, account/social tests | Document `account.encrypt_oauth_tokens`. |
| Account Linking | Ruby docs | `routes/social.rb`, `routes/account.rb`, social/account tests | Use `link_social` and account linking config. |
| Forced Linking | Ruby docs | social routes/tests | Document `trusted_providers`/Ruby account linking options after verification. |
| Manually Linking Accounts | Ruby docs | `routes/social.rb`, social tests | Use Ruby-supported manual link flow. |
| Account Unlinking | Ruby docs | `routes/account.rb`, `account_test.rb` | Use `auth.api.unlink_account`. |
