# OAuth Provider Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining Better Auth upstream `@better-auth/oauth-provider` (v1.6.9) deltas in the Ruby `better_auth-oauth-provider` port so endpoints, schema, and metadata match upstream behavior, with deviations documented and locked behind tests.

**Architecture:** Treat `upstream/packages/oauth-provider/src/`** as the source of truth for endpoint paths, request/response shapes, schema, OAuth 2.1/OIDC compliance, rate limits, and grant-type semantics. Ruby keeps `snake_case` plugin options (e.g. `login_page`, `consent_page`, `store_client_secret`) but JSON wire fields and storage column names stay `camelCase` (`clientId`, `redirectUris`, `tokenEndpointAuthMethod`). Browser-only client helpers, the React/Solid plugins, and the upstream OpenAPI metadata blocks are explicitly out of scope.

**Tech Stack:** Ruby 3.4.9, Rack 3, Minitest, StandardRB, Better Auth core endpoint/middleware/adapter contracts, `jwt` gem (RS256 + HS256), upstream Better Auth `v1.6.9`. Tests run against the in-memory adapter and against the Postgres/MySQL/SQLite adapters via `docker compose up -d`.

---

## Summary

Start with tests translated from `upstream/packages/oauth-provider/src/oauth.test.ts`, `token.test.ts`, `register.test.ts`, `metadata.test.ts`, `pkce-optional.test.ts`, and `pairwise.test.ts`, watch each fail, implement the minimum fix, then rerun focused tests. The current Ruby port covers the happy path for `authorize → consent → token → userinfo → revoke` flows, JWT/HS256 access tokens, refresh-token rotation, and consent CRUD, but diverges from upstream on:

1. **Endpoint paths and shapes for client + consent CRUD.** Upstream uses POST `/oauth2/delete-client`, GET `/oauth2/get-client?client_id=...`, POST `/oauth2/update-client`, POST `/oauth2/delete-consent`, GET `/oauth2/get-consents`. Ruby reuses `/oauth2/client` with mixed verbs (DELETE, PATCH) and adds a non-standard `/oauth2/client/:id`. Upstream also exposes admin variants under `/admin/oauth2/...` that Ruby does not register.
2. **Schema cruft on `oauthAccessToken`.** Ruby still stores `accessToken`, `refreshToken`, `accessTokenExpiresAt`, `scope`, plus the upstream `token`, `expiresAt`, `scopes`. Upstream collapsed these into the canonical `token`/`expiresAt`/`scopes` columns. Likewise `oauthConsent` carries an extra `consentGiven` boolean upstream removed.
3. `**prompt=none`, `id_token_signing_alg_values_supported`, and `token_endpoint_auth_methods_supported` discovery output.** Upstream gates `"none"` on `allowUnauthenticatedClientRegistration` and includes it in `prompt_values_supported`; Ruby unconditionally publishes `"none"` for token auth and omits it from prompt values, plus hardcodes `["HS256"]` instead of inheriting the JWT plugin's signing algorithm.
4. `**registerEndpoint` defaults and validation.** Upstream forces PKCE on dynamic registration via Zod (`require_pkce` defaults to `true`) and rejects `skip_consent` at the schema level; Ruby allows PKCE to be disabled when `dynamic_registration: false` (which is correct) but does not consistently default `require_pkce` for dynamic registration to `true` on the response, and accepts `skip_consent: false` on dynamic registration where upstream rejects any `skip_consent` key.
5. **Plugin metadata.** Ruby's `Plugin.new(id: "oauth-provider", ...)` does not expose `version` (upstream `1.6.0+` ships `version: PACKAGE_VERSION`).
6. **Refresh-token rotation database write semantics.** Upstream refresh-token rotation creates a new `oauthRefreshToken` row; Ruby creates a row but never re-checks revocation against the row when the in-memory store is bypassed (e.g. across processes), and does not invalidate the descendant access tokens through the adapter when secondary storage is enabled.
7. `**rotate-secret` field name.** Upstream returns the rotated secret in `client_secret` plus prefix, with the rest of the schema body (`schemaToOAuth`); Ruby reuses `client_response` then merges `client_secret`. Behavior is mostly the same but `client_secret_expires_at` is missing on rotate.
8. `**oauthConsent` keyed by primary id.** Upstream consent CRUD uses `id` as the lookup key; Ruby's get/update/delete look up by `client_id + user_id`. This breaks parity with the upstream JS client that stores consent ids client-side.
9. `**pairwise` subject identifier inputs.** Upstream uses `sectorIdentifier` derived from the client's redirect URIs; Ruby uses `clientId`, which is correct only when sectors are not configured. Lock the divergence behind a test or implement sector identifier support.
10. **Plain `HS256` id_token signer.** Ruby always falls back to HS256 with the gem `secret`; upstream switches signer based on the JWT plugin (`EdDSA` default, configurable) and falls back to HS256 only when `disableJwtPlugin: true`. Without an EdDSA path configured, document the Ruby-specific HS256 fallback explicitly.

The full task list below pins each delta behind a failing test, fixes it minimally, and then commits.

## Key Changes

- **Plugin metadata:** Expose `version: BetterAuth::OAuthProvider::VERSION` (parity with upstream `1.6.0+`).
- **Endpoint path realignment:** Add upstream-shaped routes alongside the existing Ruby paths and prefer the upstream shapes in tests:
  - GET `/oauth2/get-client?client_id=...` (session-protected, owner-only)
  - GET `/oauth2/get-clients` (session-protected, owner OR `referenceId` scoped)
  - POST `/oauth2/update-client` body `{ client_id, update: {...} }`
  - POST `/oauth2/delete-client` body `{ client_id }`
  - POST `/admin/oauth2/create-client` (server-only, mirrors upstream `adminCreateOAuthClient`)
  - PATCH `/admin/oauth2/update-client` (server-only, body `{ client_id, update }`)
  - GET `/oauth2/get-consent?id=...` (session-protected, owner-only via `id`)
  - GET `/oauth2/get-consents` (session-protected)
  - POST `/oauth2/update-consent` body `{ id, update: { scopes } }`
  - POST `/oauth2/delete-consent` body `{ id }`
  - GET `/oauth2/public-client?client_id=...` (session-protected, public fields only)
  - POST `/oauth2/public-client-prelogin` body `{ client_id, oauth_query? }` (publicSessionMiddleware)
  Keep the existing Ruby paths as deprecated aliases for one minor release and document the migration.
- **Schema cleanup:** Drop `accessToken`, `refreshToken`, `accessTokenExpiresAt`, `scope` from `oauthAccessToken` (keep `token`, `expiresAt`, `scopes`) and remove `consentGiven` from `oauthConsent`. Update all storage and adapter code to use the canonical names. Provide a Ruby-Rails migration helper that copies any legacy values forward then drops the columns.
- **Discovery metadata parity:**
  - `token_endpoint_auth_methods_supported` includes `"none"` only when `allow_unauthenticated_client_registration: true` (or `allow_dynamic_client_registration: true` and `token_endpoint_auth_method` allows `none`).
  - `id_token_signing_alg_values_supported` follows the JWT plugin's configured `keyPairConfig.alg` if available, falls back to `["HS256"]` only when `disable_jwt_plugin: true` is set.
  - `prompt_values_supported` includes `"none"`.
  - `subject_types_supported` toggles based on `pairwise_secret`.
- **Dynamic registration validation:** Add Zod-style schema-level rejection of `skip_consent` on `/oauth2/register` and default `require_pkce` to `true` for dynamic-registration responses.
- **Refresh rotation hardening:** When secondary storage is enabled, persist refresh-token state through the adapter and re-read it on `refresh_token` grant before consuming it. Revoke the descendant access tokens via `oauthAccessToken` `delete_many { refreshId: <id> }`.
- **Rotate-secret response fields:** Return `client_id`, `client_secret` (prefixed), `client_secret_expires_at`, and the upstream `client_response` shape. Add a regression test.
- **Pairwise subject identifier sector support:** Wire `client_data["sectorIdentifierUri"]` (or computed from registered redirect URIs) into the HMAC input. If sector resolution is intentionally postponed, lock the current `clientId` fallback behind a test and document the deviation.
- **OpenAPI metadata policy:** Document that Ruby endpoints intentionally omit upstream OpenAPI bodies; OpenAPI generation is not part of the `better_auth-oauth-provider` scope.
- **Client policy:** Document that `@better-auth/oauth-provider/client` and the React/Vue/Solid client plugins are not ported. Apps should call the JSON endpoints directly.

## File Structure


| File                                                                                                                | Responsibility                                                                                                                                                     | Action                                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`                                     | Plugin entry point, endpoint registration, rate limits, schema, metadata responses, register/admin/admin-update endpoints.                                         | Modify: register upstream-shaped routes, expose `version`, fix metadata semantics, clean dynamic registration validations.                                                 |
| `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`                                                    | Stateless protocol primitives shared by the OAuth provider plugin and tests (token issuance, refresh rotation, PKCE, client CRUD helpers, scope/audience parsing). | Modify: drop legacy access-token columns; harden refresh rotation; thread sector-identifier into pairwise; add `client_secret_expires_at` on rotate.                       |
| `packages/better_auth-oauth-provider/lib/better_auth/oauth_provider/version.rb`                                     | Gem version constant.                                                                                                                                              | Reference only (read for `version:` wiring).                                                                                                                               |
| `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`                                       | Existing Minitest suite covering authorize/consent/token/userinfo/revoke.                                                                                          | Modify: add new failing tests for each parity gap before the implementation.                                                                                               |
| `packages/better_auth-rails/lib/generators/better_auth/oauth_provider/install/install_generator.rb` (and templates) | Rails migration generator for the OAuth schema.                                                                                                                    | Modify: drop the deprecated columns and add a separate migration template that copies legacy values forward.                                                               |
| `packages/better_auth-oauth-provider/README.md`                                                                     | Documentation surface for adopters.                                                                                                                                | Modify: document upstream paths, deprecated alias paths, schema migration, intentional Ruby adaptations (HS256 fallback, no React client), and rate-limit override format. |
| `.docs/features/upstream-parity-matrix.md`                                                                          | Repo-wide parity tracker.                                                                                                                                          | Modify: bump `oauth-provider` to "100%" once Task 14 verification log is complete.                                                                                         |


The plan keeps every change inside the package boundary above. The plugin file already exists at ~960 lines; if Task 6 (admin endpoints) pushes it over ~1100 lines, split `oauth_provider_endpoints` into one helper per topic (`client_endpoints`, `consent_endpoints`, `discovery_endpoints`, `flow_endpoints`) and require them explicitly. Do not split the protocol module; tests rely on its global functions.

---

## Task List

### Task 1: Save Plan And Establish Baseline

- Create `.docs/plans/2026-04-29-oauth-provider-upstream-parity.md` with this plan.
- Run `git status --short --branch` and confirm work is on a dedicated branch (e.g. `codex/oauth-provider-upstream-diff`).
- Initialize upstream at `v1.6.9`:

```bash
git submodule update --init --recursive upstream
cd upstream && git fetch --tags origin && git checkout v1.6.9 && cd ..
```

- Run baseline package tests: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec rake test`.
- Run baseline core tests for the OAuth shim: `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/oauth_protocol_test.rb`.
- Record run counts and pre-existing failures in this plan's Verification Log section.

### Task 2: Plugin Metadata Parity (Version Field)

**Files:**

- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`
- Modify: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`
- Verify: `upstream/packages/oauth-provider/src/oauth.ts:166-170`
- **Step 1: Add a failing test**

```ruby
def test_plugin_exposes_package_version_like_upstream
  plugin = BetterAuth::Plugins.oauth_provider(login_page: "/login", consent_page: "/consent")
  assert_equal BetterAuth::OAuthProvider::VERSION, plugin.version
end
```

- **Step 2: Run test to verify it fails**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n test_plugin_exposes_package_version_like_upstream`

Expected: FAIL with `NoMethodError: undefined method 'version'` or `nil != "0.x.y"`.

- **Step 3: Wire `version:` through `Plugin.new`**

In `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`:

```ruby
require_relative "../oauth_provider/version"

Plugin.new(
  id: "oauth-provider",
  version: BetterAuth::OAuthProvider::VERSION,
  endpoints: oauth_provider_endpoints(config),
  schema: oauth_provider_schema,
  rate_limit: oauth_provider_rate_limits(config),
  options: config
)
```

If the core `BetterAuth::Plugin` does not yet accept `:version`, add the keyword in `packages/better_auth/lib/better_auth/plugin.rb` and expose a `#version` reader, defaulting to `nil` for backward compatibility.

- **Step 4: Run test to verify it passes**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n test_plugin_exposes_package_version_like_upstream`

Expected: PASS.

- **Step 5: Commit**

```bash
git add packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb \
        packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb \
        packages/better_auth/lib/better_auth/plugin.rb
git commit -m "feat(oauth-provider): expose plugin version to match upstream 1.6.0+"
```

### Task 3: Discovery Metadata Parity

**Files:**

- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`
- Modify: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`
- Verify: `upstream/packages/oauth-provider/src/metadata.ts:13-112`
- **Step 1: Add failing tests for discovery metadata**

```ruby
def test_oauth_authorization_server_metadata_excludes_none_when_unauthenticated_disabled
  auth = build_auth(scopes: ["openid", "profile", "email"])
  res = JSON.parse(auth.api.get_o_auth_server_config[:body])

  refute_includes res["token_endpoint_auth_methods_supported"], "none"
  assert_includes res["token_endpoint_auth_methods_supported"], "client_secret_basic"
  assert_includes res["token_endpoint_auth_methods_supported"], "client_secret_post"
end

def test_oauth_authorization_server_metadata_includes_none_when_unauthenticated_enabled
  auth = build_auth(allow_unauthenticated_client_registration: true)
  res = JSON.parse(auth.api.get_o_auth_server_config[:body])
  assert_includes res["token_endpoint_auth_methods_supported"], "none"
end

def test_oidc_metadata_uses_jwt_plugin_alg_when_available
  auth = build_auth(plugins: [BetterAuth::Plugins.jwt(jwks: {key_pair_config: {alg: "EdDSA"}})])
  res = JSON.parse(auth.api.get_open_id_config[:body])
  assert_equal ["EdDSA"], res["id_token_signing_alg_values_supported"]
end

def test_oidc_metadata_advertises_prompt_none
  auth = build_auth
  res = JSON.parse(auth.api.get_open_id_config[:body])
  assert_includes res["prompt_values_supported"], "none"
end
```

- **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /metadata_/`

Expected: FAIL on `excludes_none`, `includes_none_when_unauthenticated`, `id_token_signing_alg`, and `prompt_none`.

- **Step 3: Implement discovery parity**

In `oauth_server_metadata_endpoint` and `oauth_openid_metadata_endpoint`:

```ruby
def oauth_token_auth_methods(config)
  base = ["client_secret_basic", "client_secret_post"]
  base.unshift("none") if config[:allow_unauthenticated_client_registration]
  base
end

def oauth_id_token_signing_algs(ctx, config)
  return ["HS256"] if config[:disable_jwt_plugin]
  alg = config.dig(:jwt, :jwks, :key_pair_config, :alg) ||
    ctx.context.options.plugins.find { |p| p.id == "jwt" }&.options&.dig(:jwks, :key_pair_config, :alg)
  alg ? [alg] : ["EdDSA"]
end

def oauth_prompt_values
  ["login", "consent", "create", "select_account", "none"]
end
```

Use the helpers in both metadata endpoints. Confirm the `subject_types_supported` toggle stays based on `config[:pairwise_secret]`.

- **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /metadata_/`

Expected: PASS for all four.

- **Step 5: Commit**

```bash
git add packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb \
        packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb
git commit -m "fix(oauth-provider): align discovery metadata with upstream auth methods, alg, prompt"
```

### Task 4: Schema Cleanup For oauthAccessToken And oauthConsent

**Files:**

- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`
- Modify: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`
- Modify: `packages/better_auth-rails/lib/generators/better_auth/oauth_provider/install/templates/migration.rb.tt`
- Verify: `upstream/packages/oauth-provider/src/schema.ts:213-307`
- **Step 1: Add a failing schema test**

```ruby
def test_access_token_schema_matches_upstream_canonical_columns
  plugin = BetterAuth::Plugins.oauth_provider(login_page: "/login", consent_page: "/consent")
  fields = plugin.schema[:oauthAccessToken][:fields].keys

  assert_includes fields, :token
  assert_includes fields, :expiresAt
  assert_includes fields, :scopes
  refute_includes fields, :accessToken
  refute_includes fields, :refreshToken
  refute_includes fields, :accessTokenExpiresAt
  refute_includes fields, :scope
end

def test_consent_schema_drops_consent_given_column
  plugin = BetterAuth::Plugins.oauth_provider(login_page: "/login", consent_page: "/consent")
  refute_includes plugin.schema[:oauthConsent][:fields].keys, :consentGiven
end
```

- **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /schema_(matches_upstream|drops_consent)/`

Expected: FAIL.

- **Step 3: Update schema definition**

In `oauth_provider_schema` inside `lib/better_auth/plugins/oauth_provider.rb`:

```ruby
oauthAccessToken: {
  modelName: "oauthAccessToken",
  fields: {
    token: {type: "string", unique: true, required: true},
    clientId: {type: "string", required: true},
    sessionId: {type: "string", required: false},
    userId: {type: "string", required: false},
    referenceId: {type: "string", required: false},
    refreshId: {type: "string", required: false},
    expiresAt: {type: "date", required: true},
    createdAt: {type: "date", required: true, default_value: -> { Time.now }},
    scopes: {type: "string[]", required: true}
  }
},
oauthConsent: {
  modelName: "oauthConsent",
  fields: {
    clientId: {type: "string", required: true},
    userId: {type: "string", required: false},
    referenceId: {type: "string", required: false},
    scopes: {type: "string[]", required: true},
    createdAt: {type: "date", required: true, default_value: -> { Time.now }},
    updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }}
  }
}
```

In `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`, replace every `record["accessToken"]`, `record["accessTokenExpiresAt"]`, `record["refreshToken"]`, and `record["scope"]` with `record["token"]`, `record["expiresAt"]`, refresh-token id (`refreshId`), and `record["scopes"]` respectively. In `userinfo`, switch `parse_scopes(record["scope"] || record["scopes"])` to `parse_scopes(record["scopes"])`.

- **Step 4: Update consent CRUD helpers**

In `oauth_protocol.rb`, drop the `consentGiven` field from `oauth_store_consent` and `oauth_consent_response`. In `oauth_consent_granted?`, replace `consent["consentGiven"]` with the existence-check `!!consent` since rows are only inserted on grant.

- **Step 5: Update Rails migration template**

In the install generator's migration template, drop the legacy columns and add a `up` migration step that copies legacy values forward when present:

```ruby
def up
  if column_exists?(:better_auth_oauth_access_tokens, :access_token)
    execute "UPDATE better_auth_oauth_access_tokens SET token = COALESCE(token, access_token), expires_at = COALESCE(expires_at, access_token_expires_at), scopes = COALESCE(scopes, scope) WHERE token IS NULL OR scopes IS NULL"
    remove_column :better_auth_oauth_access_tokens, :access_token
    remove_column :better_auth_oauth_access_tokens, :refresh_token
    remove_column :better_auth_oauth_access_tokens, :access_token_expires_at
    remove_column :better_auth_oauth_access_tokens, :scope
  end
  if column_exists?(:better_auth_oauth_consents, :consent_given)
    execute "DELETE FROM better_auth_oauth_consents WHERE consent_given = false"
    remove_column :better_auth_oauth_consents, :consent_given
  end
end
```

- **Step 6: Run tests to verify schema cleanup passes**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec rake test`

Expected: PASS for the entire OAuth suite (including the new schema tests). Investigate any new failures from `userinfo`, refresh, or revocation tests and update the protocol module to use only the canonical columns until the suite is green.

- **Step 7: Commit**

```bash
git add packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb \
        packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb \
        packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb \
        packages/better_auth-rails/lib/generators/better_auth/oauth_provider/install/templates/migration.rb.tt
git commit -m "refactor(oauth-provider): drop legacy access-token + consent columns to match upstream"
```

### Task 5: Upstream Client CRUD Endpoint Paths

**Files:**

- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`
- Modify: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`
- Verify: `upstream/packages/oauth-provider/src/oauthClient/index.ts:235-651`
- **Step 1: Add failing tests for upstream-shaped paths**

```ruby
def test_oauth2_get_client_uses_query_param_like_upstream
  auth = build_auth
  cookie = sign_up_cookie(auth, email: "client-paths@example.com")
  registered = auth.api.create_o_auth_client(headers: {"cookie" => cookie}, body: {redirect_uris: ["https://example.com/cb"]})

  res = auth.api.get_o_auth_client(headers: {"cookie" => cookie}, query: {client_id: registered[:client_id]})
  assert_equal registered[:client_id], JSON.parse(res[:body])["client_id"]
end

def test_oauth2_get_clients_returns_owned_clients
  auth = build_auth
  cookie = sign_up_cookie(auth, email: "list-clients@example.com")
  auth.api.create_o_auth_client(headers: {"cookie" => cookie}, body: {redirect_uris: ["https://example.com/cb"]})

  res = auth.api.get_o_auth_clients(headers: {"cookie" => cookie})
  assert_equal 1, JSON.parse(res[:body]).length
end

def test_oauth2_update_client_post_with_update_envelope
  auth = build_auth
  cookie = sign_up_cookie(auth, email: "update-paths@example.com")
  registered = auth.api.create_o_auth_client(headers: {"cookie" => cookie}, body: {redirect_uris: ["https://example.com/cb"]})

  res = auth.api.update_o_auth_client(
    headers: {"cookie" => cookie},
    body: {client_id: registered[:client_id], update: {client_name: "renamed"}}
  )
  assert_equal "renamed", JSON.parse(res[:body])["client_name"]
end

def test_oauth2_delete_client_post_with_client_id_body
  auth = build_auth
  cookie = sign_up_cookie(auth, email: "delete-paths@example.com")
  registered = auth.api.create_o_auth_client(headers: {"cookie" => cookie}, body: {redirect_uris: ["https://example.com/cb"]})

  res = auth.api.delete_o_auth_client(
    headers: {"cookie" => cookie},
    body: {client_id: registered[:client_id]}
  )
  assert_equal 200, res[:status]
end

def test_oauth2_public_client_endpoint_returns_public_fields_only
  auth = build_auth
  cookie = sign_up_cookie(auth, email: "public-fields@example.com")
  registered = auth.api.create_o_auth_client(headers: {"cookie" => cookie}, body: {redirect_uris: ["https://example.com/cb"], client_name: "Public Test"})

  res = auth.api.get_o_auth_client_public(headers: {"cookie" => cookie}, query: {client_id: registered[:client_id]})
  body = JSON.parse(res[:body])
  assert_equal "Public Test", body["client_name"]
  refute body.key?("client_secret")
  refute body.key?("redirect_uris")
end
```

- **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /oauth2_(get_client|get_clients|update_client|delete_client|public_client)/`

Expected: FAIL.

- **Step 3: Add upstream-shaped endpoints**

In `oauth_provider_endpoints`, register new entries that point to upstream-shaped routes. Existing Ruby routes remain as deprecated aliases (do not delete yet):

```ruby
def oauth_get_client_endpoint(config)
  Endpoint.new(path: "/oauth2/get-client", method: "GET") do |ctx|
    session = Routes.current_session(ctx)
    oauth_assert_client_privilege!(ctx, config, session, "read")
    query = OAuthProtocol.stringify_keys(ctx.query)
    client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
    raise APIError.new("NOT_FOUND", message: "client not found") unless client
    oauth_assert_owned_client!(client, session, config)

    ctx.json(OAuthProtocol.client_response(client, include_secret: false))
  end
end

def oauth_list_clients_endpoint(config)
  Endpoint.new(path: "/oauth2/get-clients", method: "GET") do |ctx|
    session = Routes.current_session(ctx)
    oauth_assert_client_privilege!(ctx, config, session, "list")
    reference_id = config[:client_reference]&.call({user: session[:user], session: session[:session]})
    clients = if reference_id
      ctx.context.adapter.find_many(model: "oauthClient", where: [{field: "referenceId", value: reference_id}])
    else
      ctx.context.adapter.find_many(model: "oauthClient", where: [{field: "userId", value: session[:user]["id"]}])
    end
    ctx.json(clients.map { |client| OAuthProtocol.client_response(client, include_secret: false) })
  end
end

def oauth_update_client_endpoint(config)
  Endpoint.new(path: "/oauth2/update-client", method: "POST") do |ctx|
    session = Routes.current_session(ctx)
    oauth_assert_client_privilege!(ctx, config, session, "update")
    body = OAuthProtocol.stringify_keys(ctx.body)
    client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
    raise APIError.new("NOT_FOUND", message: "client not found") unless client
    oauth_assert_owned_client!(client, session, config)

    update = oauth_client_update_data(OAuthProtocol.stringify_keys(body["update"] || {}))
    updated = update.empty? ? client : ctx.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}], update: update.merge(updatedAt: Time.now))
    ctx.json(OAuthProtocol.client_response(updated, include_secret: false))
  end
end

def oauth_delete_client_endpoint(config)
  Endpoint.new(path: "/oauth2/delete-client", method: "POST") do |ctx|
    session = Routes.current_session(ctx)
    oauth_assert_client_privilege!(ctx, config, session, "delete")
    body = OAuthProtocol.stringify_keys(ctx.body)
    client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
    raise APIError.new("NOT_FOUND", message: "client not found") unless client
    oauth_assert_owned_client!(client, session, config)
    ctx.context.adapter.delete(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}])
    ctx.json({deleted: true})
  end
end

def oauth_get_client_public_endpoint(_config)
  Endpoint.new(path: "/oauth2/public-client", method: "GET", use: [:session_middleware]) do |ctx|
    Routes.current_session(ctx)
    query = OAuthProtocol.stringify_keys(ctx.query)
    client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
    raise APIError.new("NOT_FOUND", message: "client not found") unless client
    raise APIError.new("NOT_FOUND", message: "client not found") if OAuthProtocol.stringify_keys(client)["disabled"]

    ctx.json(oauth_public_client_response(client))
  end
end
```

Update `oauth_assert_owned_client!` to also accept `referenceId` ownership when `client_reference` is configured:

```ruby
def oauth_assert_owned_client!(client, session, config)
  data = OAuthProtocol.stringify_keys(client)
  return if data["userId"] && data["userId"] == session[:user]["id"]
  if data["referenceId"] && config[:client_reference].respond_to?(:call)
    return if data["referenceId"] == config[:client_reference].call(user: session[:user], session: session[:session])
  end
  raise APIError.new("NOT_FOUND", message: "client not found")
end
```

- **Step 4: Keep aliases for the legacy paths**

Register the existing `/oauth2/client/:id`, `/oauth2/clients`, `/oauth2/client` (PATCH/DELETE) endpoints as deprecated aliases that internally call the new handlers and emit a deprecation log line via `BetterAuth::Logger.warn`.

- **Step 5: Run tests to verify they pass**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /oauth2_(get_client|get_clients|update_client|delete_client|public_client)/`

Expected: PASS.

- **Step 6: Commit**

```bash
git add packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb \
        packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb
git commit -m "feat(oauth-provider): add upstream-shaped client CRUD endpoints"
```

### Task 6: Admin OAuth Client Endpoints

**Files:**

- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`
- Modify: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`
- Verify: `upstream/packages/oauth-provider/src/oauthClient/index.ts:21-565` (`adminCreateOAuthClient`, `adminUpdateOAuthClient`)
- **Step 1: Add a failing test for `/admin/oauth2/create-client`**

```ruby
def test_admin_create_oauth_client_is_server_only
  auth = build_auth
  body = {redirect_uris: ["https://admin.example.com/cb"], client_secret_expires_at: 0}

  error = assert_raises(BetterAuth::APIError) do
    auth.handler.call(env_for("POST", "/admin/oauth2/create-client", body))
  end
  assert_equal "FORBIDDEN", error.status

  res = auth.api.admin_create_o_auth_client(body: body)
  body_response = JSON.parse(res[:body])
  assert_equal 0, body_response["client_secret_expires_at"]
end
```

- **Step 2: Run tests and confirm they fail**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n test_admin_create_oauth_client_is_server_only`

Expected: FAIL because the path is currently mapped to `/oauth2/create-client` only.

- **Step 3: Implement admin endpoints**

Register two new endpoints in `oauth_provider_endpoints`:

```ruby
admin_create_o_auth_client: oauth_admin_create_client_endpoint(config),
admin_update_o_auth_client: oauth_admin_update_client_endpoint(config),
```

```ruby
def oauth_admin_create_client_endpoint(config)
  Endpoint.new(path: "/admin/oauth2/create-client", method: "POST", metadata: {server_only: true}) do |ctx|
    body = OAuthProtocol.stringify_keys(ctx.body)
    client = OAuthProtocol.create_client(
      ctx,
      model: "oauthClient",
      body: body,
      owner_session: nil,
      default_scopes: config[:client_registration_default_scopes] || config[:scopes],
      allowed_scopes: config[:client_registration_allowed_scopes] || config[:scopes],
      store_client_secret: config[:store_client_secret],
      prefix: config[:prefix],
      dynamic_registration: false,
      admin: true
    )
    ctx.json(client, status: 201, headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"})
  end
end

def oauth_admin_update_client_endpoint(_config)
  Endpoint.new(path: "/admin/oauth2/update-client", method: "PATCH", metadata: {server_only: true}) do |ctx|
    body = OAuthProtocol.stringify_keys(ctx.body)
    client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
    raise APIError.new("NOT_FOUND", message: "client not found") unless client

    update = oauth_client_update_data(OAuthProtocol.stringify_keys(body["update"] || {}))
    updated = update.empty? ? client : ctx.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}], update: update.merge(updatedAt: Time.now))
    ctx.json(OAuthProtocol.client_response(updated, include_secret: false))
  end
end
```

`OAuthProtocol.create_client` must accept `admin:` kwarg and, when true, allow `skip_consent`, `enable_end_session`, `client_secret_expires_at`, and `subject_type` to be persisted. Block these for non-admin paths in `validate_client_metadata_enums!`:

```ruby
def validate_admin_only_fields!(body, admin:)
  return if admin
  %w[skip_consent skipConsent enable_end_session enableEndSession client_secret_expires_at subject_type subjectType].each do |key|
    if body.key?(key)
      raise APIError.new("BAD_REQUEST", message: "field #{key} is server-only")
    end
  end
end
```

The shared `Routes.handle` should reject server-only routes when `ctx.request` is set (mirrors upstream's `SERVER_ONLY: true` enforcement). Ensure `Routes.server_only?(ctx)` returns true unless the request has been issued through `auth.api.*`.

- **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /admin_(create|update)_oauth_client/`

Expected: PASS.

- **Step 5: Commit**

```bash
git add packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb \
        packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb \
        packages/better_auth/lib/better_auth/routes.rb \
        packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb
git commit -m "feat(oauth-provider): expose admin OAuth client endpoints (server-only)"
```

### Task 7: Upstream Consent CRUD Endpoint Paths

**Files:**

- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`
- Modify: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`
- Verify: `upstream/packages/oauth-provider/src/oauthConsent/index.ts:11-90`, `endpoints.ts:1-162`
- **Step 1: Add failing tests**

```ruby
def test_get_oauth_consent_uses_id_query_param
  auth = build_auth(scopes: ["openid", "profile"])
  cookie, session_id, user_id = sign_up_with_session(auth)
  client = create_test_client(auth, cookie)
  consent_id = grant_consent(auth, user_id, client[:client_id], scopes: ["profile"])

  res = auth.api.get_o_auth_consent(headers: {"cookie" => cookie}, query: {id: consent_id})
  assert_equal client[:client_id], JSON.parse(res[:body])["client_id"]
end

def test_get_oauth_consents_returns_user_consents
  auth = build_auth(scopes: ["openid", "profile"])
  cookie, session_id, user_id = sign_up_with_session(auth)
  client_a = create_test_client(auth, cookie)
  client_b = create_test_client(auth, cookie)
  grant_consent(auth, user_id, client_a[:client_id], scopes: ["profile"])
  grant_consent(auth, user_id, client_b[:client_id], scopes: ["profile"])

  res = auth.api.get_o_auth_consents(headers: {"cookie" => cookie})
  assert_equal 2, JSON.parse(res[:body]).length
end

def test_update_oauth_consent_post_with_id_envelope
  auth = build_auth(scopes: ["openid", "profile", "email"])
  cookie, session_id, user_id = sign_up_with_session(auth)
  client = create_test_client(auth, cookie, scope: "profile email")
  consent_id = grant_consent(auth, user_id, client[:client_id], scopes: ["profile", "email"])

  res = auth.api.update_o_auth_consent(
    headers: {"cookie" => cookie},
    body: {id: consent_id, update: {scopes: ["profile"]}}
  )
  assert_equal ["profile"], JSON.parse(res[:body])["scopes"]
end

def test_delete_oauth_consent_post_with_id_body
  auth = build_auth(scopes: ["openid", "profile"])
  cookie, session_id, user_id = sign_up_with_session(auth)
  client = create_test_client(auth, cookie)
  consent_id = grant_consent(auth, user_id, client[:client_id], scopes: ["profile"])

  res = auth.api.delete_o_auth_consent(headers: {"cookie" => cookie}, body: {id: consent_id})
  assert_equal 200, res[:status]
end
```

(Helpers `sign_up_with_session`, `create_test_client`, `grant_consent` already exist or should be added near the top of `oauth_provider_test.rb`.)

- **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /oauth_(get|update|delete)_(consent|consents)/`

Expected: FAIL.

- **Step 3: Reimplement consent endpoints**

```ruby
def oauth_get_consent_endpoint
  Endpoint.new(path: "/oauth2/get-consent", method: "GET") do |ctx|
    session = Routes.current_session(ctx)
    id = OAuthProtocol.stringify_keys(ctx.query)["id"]
    raise APIError.new("NOT_FOUND", message: "missing id") if id.to_s.empty?
    consent = ctx.context.adapter.find_one(model: "oauthConsent", where: [{field: "id", value: id}])
    raise APIError.new("NOT_FOUND", message: "no consent") unless consent
    raise APIError.new("UNAUTHORIZED") unless OAuthProtocol.stringify_keys(consent)["userId"] == session[:user]["id"]
    ctx.json(oauth_consent_response(consent))
  end
end

def oauth_list_consents_endpoint
  Endpoint.new(path: "/oauth2/get-consents", method: "GET") do |ctx|
    session = Routes.current_session(ctx)
    consents = ctx.context.adapter.find_many(model: "oauthConsent", where: [{field: "userId", value: session[:user]["id"]}])
    ctx.json(consents.map { |consent| oauth_consent_response(consent) })
  end
end

def oauth_update_consent_endpoint(config)
  Endpoint.new(path: "/oauth2/update-consent", method: "POST") do |ctx|
    session = Routes.current_session(ctx)
    body = OAuthProtocol.stringify_keys(ctx.body)
    id = body["id"]
    raise APIError.new("NOT_FOUND", message: "missing id") if id.to_s.empty?
    consent = ctx.context.adapter.find_one(model: "oauthConsent", where: [{field: "id", value: id}])
    raise APIError.new("NOT_FOUND", message: "no consent") unless consent
    consent_data = OAuthProtocol.stringify_keys(consent)
    raise APIError.new("UNAUTHORIZED") unless consent_data["userId"] == session[:user]["id"]

    client = OAuthProtocol.find_client(ctx, "oauthClient", consent_data["clientId"])
    allowed = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(client || {})["scopes"] || config[:scopes])
    requested = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(body["update"] || {})["scopes"] || [])
    unless requested.all? { |scope| allowed.include?(scope) }
      raise APIError.new("BAD_REQUEST", message: "invalid_scope")
    end

    updated = ctx.context.adapter.update(
      model: "oauthConsent",
      where: [{field: "id", value: id}],
      update: {scopes: requested, updatedAt: Time.now}
    )
    ctx.json(oauth_consent_response(updated))
  end
end

def oauth_delete_consent_endpoint
  Endpoint.new(path: "/oauth2/delete-consent", method: "POST") do |ctx|
    session = Routes.current_session(ctx)
    body = OAuthProtocol.stringify_keys(ctx.body)
    id = body["id"]
    raise APIError.new("NOT_FOUND", message: "missing id") if id.to_s.empty?
    consent = ctx.context.adapter.find_one(model: "oauthConsent", where: [{field: "id", value: id}])
    raise APIError.new("NOT_FOUND", message: "no consent") unless consent
    raise APIError.new("UNAUTHORIZED") unless OAuthProtocol.stringify_keys(consent)["userId"] == session[:user]["id"]

    ctx.context.adapter.delete(model: "oauthConsent", where: [{field: "id", value: id}])
    ctx.json({deleted: true})
  end
end
```

Keep the legacy `/oauth2/consent` (PATCH/DELETE/GET when `client_id` is in query) routes as deprecated aliases to avoid breaking existing apps.

- **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /oauth_(get|update|delete)_(consent|consents)/`

Expected: PASS.

- **Step 5: Commit**

```bash
git add packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb \
        packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb
git commit -m "feat(oauth-provider): add upstream-shaped consent CRUD endpoints"
```

### Task 8: Dynamic Client Registration Validation

**Files:**

- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`
- Modify: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`
- Verify: `upstream/packages/oauth-provider/src/oauth.ts:1144-1186`, `register.ts:1-484`
- **Step 1: Add failing tests**

```ruby
def test_dynamic_registration_rejects_skip_consent
  auth = build_auth(allow_dynamic_client_registration: true)
  error = assert_raises(BetterAuth::APIError) do
    auth.api.register_o_auth_client(body: {redirect_uris: ["https://x.example/cb"], skip_consent: false})
  end
  assert_equal "BAD_REQUEST", error.status
end

def test_dynamic_registration_defaults_require_pkce_to_true
  auth = build_auth(allow_dynamic_client_registration: true, allow_unauthenticated_client_registration: true)
  res = auth.api.register_o_auth_client(body: {redirect_uris: ["https://x.example/cb"]})
  body = JSON.parse(res[:body])
  assert_equal true, body["require_pkce"]
end

def test_dynamic_registration_rejects_require_pkce_false
  auth = build_auth(allow_dynamic_client_registration: true)
  error = assert_raises(BetterAuth::APIError) do
    auth.api.register_o_auth_client(body: {redirect_uris: ["https://x.example/cb"], require_pkce: false})
  end
  assert_equal "BAD_REQUEST", error.status
  assert_match(/pkce is required/i, error.message)
end
```

- **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /dynamic_registration_/`

Expected: FAIL on `defaults_require_pkce_to_true` and `rejects_skip_consent`.

- **Step 3: Update validation in `oauth_register_client_endpoint` and `OAuthProtocol.create_client`**

```ruby
# in oauth_register_client_endpoint
if body.key?("skip_consent") || body.key?("skipConsent")
  raise APIError.new("BAD_REQUEST", message: "skip_consent is not allowed during dynamic client registration")
end
body["require_pkce"] = true unless body.key?("require_pkce") || body.key?("requirePKCE")
```

In `OAuthProtocol.create_client`, set `require_pkce` to `true` by default for dynamic registration if missing, then keep `validate_client_registration!` raising on `false`. Ensure `client_response` returns `require_pkce: true` when defaulted.

- **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /dynamic_registration_/`

Expected: PASS.

- **Step 5: Commit**

```bash
git add packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb \
        packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb \
        packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb
git commit -m "fix(oauth-provider): tighten dynamic-registration validation (skip_consent, require_pkce)"
```

### Task 9: Refresh-Token Rotation Hardening

**Files:**

- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`
- Modify: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`
- Verify: `upstream/packages/oauth-provider/src/token.ts:300-560`, `revoke.ts`
- **Step 1: Add a failing test for replay detection through the adapter**

```ruby
def test_refresh_token_replay_revokes_descendant_access_tokens
  auth = build_auth(scopes: ["openid", "offline_access"])
  client_data = create_confidential_client(auth, scopes: "openid offline_access")
  refresh_token, access_token = run_authorization_code_flow(auth, client_data, scopes: "openid offline_access")
  rotated = auth.api.o_auth2_token(body: refresh_grant_body(client_data, refresh_token))

  refute_equal access_token, JSON.parse(rotated[:body])["access_token"]

  error = assert_raises(BetterAuth::APIError) do
    auth.api.o_auth2_token(body: refresh_grant_body(client_data, refresh_token))
  end
  assert_equal "BAD_REQUEST", error.status

  introspect = auth.api.o_auth2_introspect(body: {token: access_token, client_id: client_data[:client_id], client_secret: client_data[:client_secret]})
  body = JSON.parse(introspect[:body])
  assert_equal false, body["active"]

  introspect_new = auth.api.o_auth2_introspect(body: {token: JSON.parse(rotated[:body])["access_token"], client_id: client_data[:client_id], client_secret: client_data[:client_secret]})
  assert_equal false, JSON.parse(introspect_new[:body])["active"]
end
```

- **Step 2: Run test to verify it fails**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n test_refresh_token_replay_revokes_descendant_access_tokens`

Expected: FAIL because Ruby currently only revokes via the in-memory `store` map and does not delete descendant access tokens through the adapter.

- **Step 3: Harden `OAuthProtocol.refresh_tokens` and `revoke_refresh_family!`**

In `oauth_protocol.rb`:

```ruby
def refresh_tokens(ctx, store, model:, client:, refresh_token:, ...)
  refresh_token_value = strip_prefix(refresh_token, prefix, :refresh_token)
  data = lookup_refresh_record(ctx, store, refresh_token_value)
  raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless data
  if data["revoked"]
    revoke_refresh_family!(ctx, store, data)
    raise APIError.new("BAD_REQUEST", message: "invalid_grant")
  end
  raise APIError.new("BAD_REQUEST", message: "invalid_grant") if data["expiresAt"] && data["expiresAt"] <= Time.now

  # ... existing scope checks ...

  data["revoked"] = Time.now
  if data["id"] && schema_model?(ctx, "oauthRefreshToken")
    ctx.context.adapter.update(
      model: "oauthRefreshToken",
      where: [{field: "id", value: data["id"]}],
      update: {revoked: data["revoked"]}
    )
  end

  # ... call issue_tokens ...
end

def lookup_refresh_record(ctx, store, refresh_token_value)
  return nil if refresh_token_value.to_s.empty?
  data = store[:refresh_tokens][refresh_token_value]
  return data if data
  return nil unless schema_model?(ctx, "oauthRefreshToken")
  row = ctx.context.adapter.find_one(model: "oauthRefreshToken", where: [{field: "token", value: refresh_token_value}])
  return nil unless row
  hydrated = stringify_keys(row).merge(
    "user" => fetch_user(ctx, row["userId"]),
    "session" => fetch_session(ctx, row["sessionId"]),
    "scope" => scope_string(row["scopes"])
  )
  store[:refresh_tokens][refresh_token_value] = hydrated
  hydrated
end

def revoke_refresh_family!(ctx, store, refresh_record)
  client_id = refresh_record["clientId"]
  user_id = refresh_record["userId"]
  store[:refresh_tokens].delete_if { |_token, record| record["clientId"] == client_id && record["userId"] == user_id }
  store[:tokens].delete_if { |_token, record| record["clientId"] == client_id && record["userId"] == user_id }
  return unless schema_model?(ctx, "oauthRefreshToken")

  refresh_ids = ctx.context.adapter.find_many(model: "oauthRefreshToken", where: [
    {field: "clientId", value: client_id},
    {field: "userId", value: user_id}
  ]).map { |entry| stringify_keys(entry)["id"] }

  ctx.context.adapter.delete_many(model: "oauthRefreshToken", where: [
    {field: "clientId", value: client_id},
    {field: "userId", value: user_id}
  ])

  return unless schema_model?(ctx, "oauthAccessToken")
  refresh_ids.each_slice(50) do |slice|
    ctx.context.adapter.delete_many(model: "oauthAccessToken", where: [{field: "refreshId", value: slice, operator: "in"}])
  end
end
```

`fetch_user` and `fetch_session` look up the row by id when only the row exists in the database.

- **Step 4: Run test to verify it passes**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n test_refresh_token_replay_revokes_descendant_access_tokens`

Expected: PASS.

- **Step 5: Commit**

```bash
git add packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb \
        packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb
git commit -m "fix(oauth-provider): persist refresh rotation state through the adapter and cascade revoke"
```

### Task 10: Rotate Client Secret Response Parity

**Files:**

- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`
- Modify: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`
- Verify: `upstream/packages/oauth-provider/src/oauthClient/endpoints.ts:247-320`
- **Step 1: Add a failing test**

```ruby
def test_rotate_client_secret_returns_full_response_with_expires_at
  auth = build_auth
  cookie = sign_up_cookie(auth, email: "rotate-secret@example.com")
  registered = auth.api.create_o_auth_client(headers: {"cookie" => cookie}, body: {redirect_uris: ["https://example.com/cb"]})

  res = auth.api.rotate_o_auth_client_secret(headers: {"cookie" => cookie}, body: {client_id: registered[:client_id]})
  body = JSON.parse(res[:body])

  assert_equal registered[:client_id], body["client_id"]
  assert body["client_secret"]
  assert body["client_secret"].start_with?(BetterAuth::Plugins::OAuthProvider.client_secret_prefix(auth.options.plugins))
  assert_equal 0, body["client_secret_expires_at"]
end
```

- **Step 2: Run test to verify it fails**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n test_rotate_client_secret_returns_full_response_with_expires_at`

Expected: FAIL because Ruby's `oauth_rotate_client_secret_endpoint` does not return `client_secret_expires_at`.

- **Step 3: Update endpoint**

```ruby
def oauth_rotate_client_secret_endpoint(config)
  Endpoint.new(path: "/oauth2/client/rotate-secret", method: "POST") do |ctx|
    session = Routes.current_session(ctx)
    oauth_assert_client_privilege!(ctx, config, session, "rotate")
    body = OAuthProtocol.stringify_keys(ctx.body)
    client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
    raise APIError.new("NOT_FOUND", message: "client not found") unless client
    oauth_assert_owned_client!(client, session, config)
    client_data = OAuthProtocol.stringify_keys(client)
    raise APIError.new("BAD_REQUEST", message: "public clients cannot rotate secrets") if client_data["public"] || client_data["tokenEndpointAuthMethod"] == "none"

    client_secret = config[:generate_client_secret]&.call || Crypto.random_string(32)
    updated = ctx.context.adapter.update(
      model: "oauthClient",
      where: [{field: "clientId", value: body["client_id"]}],
      update: {clientSecret: OAuthProtocol.store_client_secret_value(ctx, client_secret, config[:store_client_secret]), updatedAt: Time.now}
    )
    response = OAuthProtocol.client_response(updated, include_secret: false).merge(
      client_secret: OAuthProtocol.apply_prefix(client_secret, config[:prefix], :client_secret),
      client_secret_expires_at: client_data["clientSecretExpiresAt"] || 0
    )
    ctx.json(response)
  end
end
```

- **Step 4: Run test to verify it passes**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n test_rotate_client_secret_returns_full_response_with_expires_at`

Expected: PASS.

- **Step 5: Commit**

```bash
git add packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb \
        packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb
git commit -m "fix(oauth-provider): return client_secret_expires_at on rotate-secret"
```

### Task 11: Pairwise Subject Identifier Sector Support

**Files:**

- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`
- Modify: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`
- Verify: `upstream/packages/oauth-provider/src/utils.ts` (search `resolveSubjectIdentifier`), `pairwise.test.ts:1-569`
- **Step 1: Add a failing test asserting upstream sector behavior**

```ruby
def test_pairwise_subject_uses_sector_identifier_from_redirect_uris
  auth = build_auth(pairwise_secret: "pairwise-secret-with-32-character-min-length-1234", scopes: ["openid"])
  client_a = create_pairwise_client(auth, redirect_uris: ["https://app.example.com/cb"])
  client_b = create_pairwise_client(auth, redirect_uris: ["https://app.example.com/other"])
  client_c = create_pairwise_client(auth, redirect_uris: ["https://other-app.example/cb"])

  sub_a = pairwise_sub_for(auth, client_a)
  sub_b = pairwise_sub_for(auth, client_b)
  sub_c = pairwise_sub_for(auth, client_c)

  assert_equal sub_a, sub_b
  refute_equal sub_a, sub_c
end
```

- **Step 2: Run test and confirm it fails**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n test_pairwise_subject_uses_sector_identifier_from_redirect_uris`

Expected: FAIL because Ruby uses `clientId` for the sector input.

- **Step 3: Implement sector identifier**

In `oauth_protocol.rb`:

```ruby
def subject_identifier(user_id, client, pairwise_secret)
  data = stringify_keys(client)
  return user_id unless data["subjectType"] == "pairwise" && pairwise_secret && user_id

  sector = sector_identifier(data)
  OpenSSL::HMAC.hexdigest("SHA256", pairwise_secret.to_s, "#{sector}:#{user_id}")
end

def sector_identifier(client_data)
  return URI.parse(client_data["sectorIdentifierUri"]).host if client_data["sectorIdentifierUri"].to_s.length.positive?
  redirects = client_redirect_uris(client_data)
  hosts = redirects.map { |uri| URI.parse(uri).host }.compact.uniq
  raise APIError.new("BAD_REQUEST", message: "pairwise subject_type requires a single sector when sectorIdentifierUri is unset") if hosts.length > 1
  hosts.first || client_data["clientId"]
rescue URI::InvalidURIError
  client_data["clientId"]
end
```

Verify all callers of `subject_identifier` (`issue_tokens`, `userinfo`) keep using the new derivation. Add a regression test that asserts the multi-host failure path.

- **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /pairwise_(subject|requires_single_sector)/`

Expected: PASS.

- **Step 5: Commit**

```bash
git add packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb \
        packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb
git commit -m "fix(oauth-provider): derive pairwise subject from sector identifier"
```

### Task 12: PKCE Optional, Resource Audience, And Grant-Type Edge Cases

**Files:**

- Modify: `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`
- Modify: `packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb`
- Verify: `upstream/packages/oauth-provider/src/pkce-optional.test.ts:1-697`, `token.test.ts:1-2583`
- **Step 1: Port high-value failing test cases**

Translate three tests from upstream:

```ruby
def test_token_endpoint_unsupported_grant_type_returns_oauth_error
  auth = build_auth(grant_types: ["authorization_code"])
  error = assert_raises(BetterAuth::APIError) do
    auth.api.o_auth2_token(body: {grant_type: "client_credentials", client_id: "x", client_secret: "y"})
  end
  body = JSON.parse(error.body)
  assert_equal "unsupported_grant_type", body["error"]
end

def test_authorize_resource_param_must_match_valid_audiences
  auth = build_auth(valid_audiences: ["https://api.example/mcp"])
  client = create_confidential_client(auth)
  error = assert_raises(BetterAuth::APIError) do
    auth.api.o_auth2_token(body: refresh_grant_body(client, "irrelevant").merge(resource: "https://other.example/mcp"))
  end
  assert_match(/requested resource invalid/, error.message)
end

def test_pkce_optional_for_confidential_clients_when_not_required
  auth = build_auth(scopes: ["openid"])
  client = create_confidential_client(auth, require_pkce: false)
  redirect = follow_authorize(auth, client_id: client[:client_id], scopes: "openid")
  assert_redirect_includes redirect, "code"
end
```

- **Step 2: Run tests to verify they fail**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /token_endpoint|authorize_resource|pkce_optional/`

Expected: at least one FAIL (PKCE optional path is currently unconditionally required when `requirePKCE` is unset).

- **Step 3: Implement parity**
- In `oauth_token_endpoint`, if `body["grant_type"]` is missing or not in `config[:grant_types]`, raise `APIError.new("BAD_REQUEST", message: "unsupported_grant_type")` with body `{error: "unsupported_grant_type", error_description: "unsupported grant_type ..."}`.
- In `oauth_validate_resource!`, ensure `valid_audiences` defaults to `[ctx.context.base_url]` only when explicitly set; otherwise allow any resource matching the configured list. Mirror upstream `requested resource invalid` error.
- In `OAuthProtocol.pkce_required?`, change the default fallback for `requirePKCE.nil?` to follow upstream's `requirePKCE !== false` semantics: PKCE is required only when `client["requirePKCE"]` is truthy or unset; if explicitly `false`, PKCE is optional unless `offline_access` is requested.
- **Step 4: Run tests to verify they pass**

Run: `cd packages/better_auth-oauth-provider && rbenv exec bundle exec ruby -Itest test/better_auth/oauth_provider_test.rb -n /token_endpoint|authorize_resource|pkce_optional/`

Expected: PASS.

- **Step 5: Commit**

```bash
git add packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb \
        packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb \
        packages/better_auth-oauth-provider/test/better_auth/oauth_provider_test.rb
git commit -m "fix(oauth-provider): align grant-type, resource validation, and PKCE optional semantics"
```

### Task 13: Documentation And Intentional Adaptations

**Files:**

- Modify: `packages/better_auth-oauth-provider/README.md`
- Modify: `packages/better_auth-oauth-provider/CHANGELOG.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Document the upstream-shaped routes added in Tasks 5-7 (`/oauth2/get-client`, `/oauth2/get-clients`, `/oauth2/update-client`, `/oauth2/delete-client`, `/oauth2/public-client`, `/oauth2/get-consent`, `/oauth2/get-consents`, `/oauth2/update-consent`, `/oauth2/delete-consent`, `/admin/oauth2/create-client`, `/admin/oauth2/update-client`).
- Document the deprecated Ruby aliases (`/oauth2/client/:id`, PATCH/DELETE `/oauth2/client`, `/oauth2/clients`, `/oauth2/consent`, `/oauth2/consents`) and their replacement targets, with a removal target version.
- Document the schema migration: dropped `oauthAccessToken#access_token`, `oauthAccessToken#refresh_token`, `oauthAccessToken#access_token_expires_at`, `oauthAccessToken#scope`; dropped `oauthConsent#consent_given`. Include the Rails migration template path and the SQL fallback for non-Rails apps.
- Document the Ruby-specific HS256 fallback when `disable_jwt_plugin: true` and the `EdDSA` default when the JWT plugin is registered.
- Document the rate-limit option shape: `rate_limit: {token: {window: Integer, max: Integer}, authorize: ..., introspect: ..., revoke: ..., register: ..., userinfo: ..., end_session: false}` with `false` to disable.
- Document that the upstream OpenAPI metadata blocks in route definitions are intentionally not ported.
- Document that `@better-auth/oauth-provider/client`, the React/Solid plugins, and the dashboard UI are not ported. Apps interact via JSON requests directly.
- Update `.docs/features/upstream-parity-matrix.md` to mark `oauth-provider` as "100%" with the `1.6.9` upstream tag pinned and link this plan as the last verification entry.

### Task 14: Final Verification

- Run `cd packages/better_auth-oauth-provider && rbenv exec bundle exec rake test`.
- Run `cd packages/better_auth-oauth-provider && RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb`.
- Run `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/oauth_protocol_test.rb` (core shim).
- Run `docker compose up -d` from repo root and `cd packages/better_auth && rbenv exec bundle exec rake test` to confirm the OAuth flow does not regress under Postgres/MySQL/SQLite adapters.
- Run `cd packages/better_auth-rails && rbenv exec bundle exec rake test` to validate the regenerated migration template.
- Record exact run counts for every command above in this plan's Verification Log section before marking complete.

## Assumptions

- "100%" means **100% closure of upstream `@better-auth/oauth-provider` server differences for the Ruby port**, plus explicit documentation for non-applicable client behavior and intentional Ruby adaptations (HS256 fallback when no JWT plugin is configured).
- Ruby keeps `snake_case` public APIs and `camelCase` storage column names unless a failing compatibility test proves a change.
- The current `defer_jwt` / sector identifier policy is acceptable as long as Task 11's regression test locks it.
- No version bumps or commits are part of this plan unless explicitly requested.

## Verification Log

- (fill in after each `rake test` and `standardrb` run with run counts and elapsed time)

