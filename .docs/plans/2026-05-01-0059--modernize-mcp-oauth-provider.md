# MCP OAuth Provider Modernization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Ruby MCP plugin's OIDC-provider-era internals with OAuth Provider-style behavior while keeping MCP tests split by responsibility and preserving compatibility deliberately.

**Architecture:** `BetterAuth::Plugins.mcp` remains the public entry point in `better_auth`, but the implementation moves out of the current monolithic `packages/better_auth/lib/better_auth/plugins/mcp.rb` into focused files under `packages/better_auth/lib/better_auth/plugins/mcp/`. The modern path uses OAuth Provider canonical concepts: `oauthClient`, `oauthAccessToken`, `oauthConsent`, `/oauth2/*` endpoints in metadata, JWT resource access tokens for MCP resources, and a small MCP resource handler analogous to upstream `upstream/packages/oauth-provider/src/mcp.ts`. Legacy `/mcp/*` endpoints should remain only as compatibility aliases during this migration and delegate to the same code paths.

**Tech Stack:** Ruby, Minitest, Rack mock requests, BetterAuth plugin system, `OAuthProtocol`, JWT/JWKS plugin, upstream Better Auth `v1.6.9` source and tests.

---

## Required Upstream Context

Read these upstream files before implementation:

- `upstream/packages/better-auth/src/plugins/mcp/index.ts`
- `upstream/packages/better-auth/src/plugins/mcp/authorize.ts`
- `upstream/packages/better-auth/src/plugins/mcp/mcp.test.ts`
- `upstream/packages/oauth-provider/src/mcp.ts`
- `upstream/packages/oauth-provider/src/mcp.test.ts`
- `upstream/packages/oauth-provider/src/oauth.ts`
- `upstream/packages/oauth-provider/src/token.ts`
- `upstream/packages/oauth-provider/src/introspect.ts`
- `upstream/packages/oauth-provider/src/revoke.ts`

Read these Ruby files before implementation:

- `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- `packages/better_auth/lib/better_auth/plugins/oauth_protocol.rb`
- `packages/better_auth/lib/better_auth/plugins/oidc_provider.rb`
- `packages/better_auth-oauth-provider/lib/better_auth/plugins/oauth_provider.rb`
- `packages/better_auth/test/better_auth/plugins/mcp_test.rb`
- `packages/better_auth-oauth-provider/test/support/oauth_provider_flow_helpers.rb`

## Target File Structure

Create these implementation files:

- `packages/better_auth/lib/better_auth/plugins/mcp/config.rb`: normalize MCP options and expose constants for default scopes, grant types, metadata paths, and legacy aliases.
- `packages/better_auth/lib/better_auth/plugins/mcp/metadata.rb`: build OAuth authorization-server metadata and protected-resource metadata.
- `packages/better_auth/lib/better_auth/plugins/mcp/registration.rb`: register MCP clients using the canonical `oauthClient` model.
- `packages/better_auth/lib/better_auth/plugins/mcp/authorization.rb`: authorize MCP OAuth requests, restore login prompts, handle consent redirects, validate scopes, redirect URIs, PKCE, and prompt semantics.
- `packages/better_auth/lib/better_auth/plugins/mcp/token.rb`: exchange authorization codes, refresh tokens, and issue JWT resource access tokens through `OAuthProtocol`.
- `packages/better_auth/lib/better_auth/plugins/mcp/userinfo.rb`: serve userinfo and `get_mcp_session` from canonical access token records and JWT resource access tokens.
- `packages/better_auth/lib/better_auth/plugins/mcp/resource_handler.rb`: Ruby equivalent of upstream `oauth-provider/src/mcp.ts` for `WWW-Authenticate` resource metadata and protected Rack handlers.
- `packages/better_auth/lib/better_auth/plugins/mcp/schema.rb`: expose MCP schema as OAuth Provider-style `oauthClient`, `oauthAccessToken`, and `oauthConsent`; do not register `oauthApplication`.
- `packages/better_auth/lib/better_auth/plugins/mcp/legacy_aliases.rb`: define `/mcp/register`, `/mcp/authorize`, `/mcp/token`, `/mcp/userinfo`, `/mcp/get-session`, and `/mcp/jwks` aliases that delegate to the same internal methods.
- `packages/better_auth/lib/better_auth/plugins/mcp.rb`: become a thin loader and plugin assembler.

Create these tests, split by behavior:

- `packages/better_auth/test/better_auth/plugins/mcp/test_helper.rb`
- `packages/better_auth/test/better_auth/plugins/mcp/metadata_test.rb`
- `packages/better_auth/test/better_auth/plugins/mcp/registration_test.rb`
- `packages/better_auth/test/better_auth/plugins/mcp/authorization_test.rb`
- `packages/better_auth/test/better_auth/plugins/mcp/token_test.rb`
- `packages/better_auth/test/better_auth/plugins/mcp/userinfo_test.rb`
- `packages/better_auth/test/better_auth/plugins/mcp/resource_handler_test.rb`
- `packages/better_auth/test/better_auth/plugins/mcp/legacy_aliases_test.rb`

Remove the old all-in-one test after the split is green:

- Delete: `packages/better_auth/test/better_auth/plugins/mcp_test.rb`

## Behavioral Requirements

- MCP metadata should advertise OAuth Provider-style endpoints: `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/register`, `/oauth2/introspect`, `/oauth2/revoke`, and JWKS from the JWT plugin when configured.
- Protected resource metadata should follow OAuth Protected Resource Metadata shape: `resource`, `authorization_servers`, `jwks_uri`, `scopes_supported`, `bearer_methods_supported`, and `resource_signing_alg_values_supported`.
- MCP dynamic registration should create `oauthClient` records, not `oauthApplication` records.
- Public clients should use `token_endpoint_auth_method: "none"` and require PKCE for authorization-code exchange.
- Confidential clients should support `client_secret_basic` and `client_secret_post`.
- Authorization code, refresh token, userinfo, login prompt restore, consent prompt, invalid scope, invalid redirect URI, and invalid PKCE behavior should keep current Ruby coverage and port matching upstream MCP cases.
- Resource access tokens should be JWTs when a `resource` audience is requested and should be usable by the MCP resource handler.
- Legacy `/mcp/*` routes should continue to pass existing tests during the transition, but the new metadata must point clients at `/oauth2/*`.
- `BetterAuth::Plugins::MCP.with_mcp_auth` should remain public, but internally it should use the new resource handler and support the upstream resource-metadata header rules.

---

### Task 1: Split Existing MCP Test Helpers

**Files:**
- Create: `packages/better_auth/test/better_auth/plugins/mcp/test_helper.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/mcp_test.rb`

- [x] **Step 1: Create shared MCP test helper**

Add this file so every split test uses the same setup:

```ruby
# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "rack/mock"
require_relative "../../../test_helper"

module MCPTestHelpers
  SECRET = "phase-eleven-secret-with-enough-entropy-123"

  def build_mcp_auth(options = {}, extra_plugins: [])
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.mcp({login_page: "/login"}.merge(options)), *extra_plugins]
    )
  end

  def sign_up_cookie(auth, email: "mcp@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "MCP User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def pkce_verifier
    "mcp-code-verifier-123456789012345678901234567890"
  end

  def pkce_challenge(verifier = pkce_verifier)
    Base64.urlsafe_encode64(OpenSSL::Digest.digest("SHA256", verifier), padding: false)
  end

  def register_public_mcp_client(auth, redirect_uri: "https://mcp.example/callback", scope: "openid profile email offline_access")
    auth.api.mcp_register(
      body: {
        redirect_uris: [redirect_uri],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "MCP Public Client",
        scope: scope
      }
    )
  end

  def authorize_mcp_code(auth, cookie, client, redirect_uri: "https://mcp.example/callback", scope: "openid email offline_access", state: "mcp-state", verifier: pkce_verifier, resource: nil, prompt: nil)
    query = {
      response_type: "code",
      client_id: client[:client_id],
      redirect_uri: redirect_uri,
      scope: scope,
      state: state,
      code_challenge: pkce_challenge(verifier),
      code_challenge_method: "S256"
    }
    query[:resource] = resource if resource
    query[:prompt] = prompt if prompt

    status, headers, _body = auth.api.mcp_o_auth_authorize(
      headers: {"cookie" => cookie},
      query: query,
      as_response: true
    )

    assert_equal 302, status
    Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query).fetch("code")
  end

  def exchange_mcp_code(auth, client, code, redirect_uri: "https://mcp.example/callback", verifier: pkce_verifier, resource: nil)
    body = {
      grant_type: "authorization_code",
      code: code,
      redirect_uri: redirect_uri,
      client_id: client[:client_id],
      code_verifier: verifier
    }
    body[:resource] = resource if resource
    auth.api.mcp_o_auth_token(body: body)
  end
end
```

- [x] **Step 2: Run the current MCP test file**

Run:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp_test.rb
```

Expected: the existing monolithic file still passes before splitting.

- [x] **Step 3: Commit the helper-only change**

```bash
git add packages/better_auth/test/better_auth/plugins/mcp/test_helper.rb
git commit -m "test: add shared mcp test helpers"
```

---

### Task 2: Split MCP Tests By Responsibility

**Files:**
- Create: `packages/better_auth/test/better_auth/plugins/mcp/metadata_test.rb`
- Create: `packages/better_auth/test/better_auth/plugins/mcp/registration_test.rb`
- Create: `packages/better_auth/test/better_auth/plugins/mcp/authorization_test.rb`
- Create: `packages/better_auth/test/better_auth/plugins/mcp/token_test.rb`
- Create: `packages/better_auth/test/better_auth/plugins/mcp/userinfo_test.rb`
- Create: `packages/better_auth/test/better_auth/plugins/mcp/resource_handler_test.rb`
- Create: `packages/better_auth/test/better_auth/plugins/mcp/legacy_aliases_test.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/mcp_test.rb`

- [x] **Step 1: Create metadata tests**

Create `metadata_test.rb`:

```ruby
# frozen_string_literal: true

require_relative "test_helper"

class BetterAuthPluginsMCPMetadataTest < Minitest::Test
  include MCPTestHelpers

  def test_mcp_metadata_advertises_oauth_provider_endpoints
    auth = build_mcp_auth(scopes: %w[openid profile email offline_access greeting])

    metadata = auth.api.get_mcp_o_auth_config

    assert_equal "http://localhost:3000", metadata[:issuer]
    assert_equal "http://localhost:3000/api/auth/oauth2/authorize", metadata[:authorization_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/token", metadata[:token_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/register", metadata[:registration_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/introspect", metadata[:introspection_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/revoke", metadata[:revocation_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/userinfo", metadata[:userinfo_endpoint]
    assert_includes metadata[:grant_types_supported], "authorization_code"
    assert_includes metadata[:grant_types_supported], "refresh_token"
    assert_includes metadata[:grant_types_supported], "client_credentials"
    assert_includes metadata[:token_endpoint_auth_methods_supported], "none"
    assert_equal ["S256"], metadata[:code_challenge_methods_supported]
  end

  def test_mcp_protected_resource_metadata_supports_nested_resource_paths
    auth = build_mcp_auth(resource: "http://localhost:5000/mcp", scopes: %w[openid greeting])

    metadata = auth.api.get_mcp_protected_resource

    assert_equal "http://localhost:5000/mcp", metadata[:resource]
    assert_equal ["http://localhost:3000"], metadata[:authorization_servers]
    assert_equal ["header"], metadata[:bearer_methods_supported]
    assert_includes metadata[:scopes_supported], "greeting"
  end
end
```

- [x] **Step 2: Create registration tests**

Create `registration_test.rb`:

```ruby
# frozen_string_literal: true

require_relative "test_helper"

class BetterAuthPluginsMCPRegistrationTest < Minitest::Test
  include MCPTestHelpers

  def test_register_public_client_uses_oauth_client_schema
    auth = build_mcp_auth

    client = register_public_mcp_client(auth)

    assert client[:client_id]
    assert_nil client[:client_secret]
    assert_equal "none", client[:token_endpoint_auth_method]
    assert_equal true, client[:public]
    assert auth.context.adapter.find_one(model: "oauthClient", where: [{field: "clientId", value: client[:client_id]}])
    refute auth.context.adapter.find_one(model: "oauthApplication", where: [{field: "clientId", value: client[:client_id]}])
  end

  def test_register_confidential_client_supports_basic_auth
    auth = build_mcp_auth

    client = auth.api.mcp_register(
      body: {
        redirect_uris: ["https://mcp.example/confidential"],
        token_endpoint_auth_method: "client_secret_basic",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "MCP Confidential Client"
      }
    )

    assert client[:client_id]
    assert client[:client_secret]
    assert_equal "client_secret_basic", client[:token_endpoint_auth_method]
    assert_equal false, client[:public]
  end
end
```

- [x] **Step 3: Create authorization tests**

Create `authorization_test.rb`:

```ruby
# frozen_string_literal: true

require_relative "test_helper"

class BetterAuthPluginsMCPAuthorizationTest < Minitest::Test
  include MCPTestHelpers

  def test_authorize_public_client_with_pkce_returns_code
    auth = build_mcp_auth
    cookie = sign_up_cookie(auth)
    client = register_public_mcp_client(auth)

    code = authorize_mcp_code(auth, cookie, client)

    assert_match(/\A[A-Za-z0-9_-]{32,}\z/, code)
  end

  def test_authorize_rejects_invalid_scope_and_missing_pkce
    auth = build_mcp_auth(require_pkce: true, scopes: %w[openid email])
    cookie = sign_up_cookie(auth)
    client = register_public_mcp_client(auth, scope: "openid email")

    invalid_scope = auth.api.mcp_o_auth_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://mcp.example/callback",
        scope: "openid missing"
      },
      as_response: true
    )

    assert_equal 302, invalid_scope.first
    assert_includes invalid_scope[1].fetch("location"), "error=invalid_scope"

    missing_pkce = auth.api.mcp_o_auth_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://mcp.example/callback",
        scope: "openid"
      },
      as_response: true
    )

    assert_equal 302, missing_pkce.first
    assert_includes missing_pkce[1].fetch("location"), "error=invalid_request"
    assert_includes missing_pkce[1].fetch("location"), "pkce+is+required"
  end
end
```

- [x] **Step 4: Create token tests**

Create `token_test.rb`:

```ruby
# frozen_string_literal: true

require "jwt"
require_relative "test_helper"

class BetterAuthPluginsMCPTokenTest < Minitest::Test
  include MCPTestHelpers

  def test_authorization_code_and_refresh_flow
    auth = build_mcp_auth
    cookie = sign_up_cookie(auth)
    client = register_public_mcp_client(auth)
    code = authorize_mcp_code(auth, cookie, client)

    tokens = exchange_mcp_code(auth, client, code)

    assert_equal "Bearer", tokens[:token_type]
    assert tokens[:access_token]
    assert tokens[:refresh_token]

    refreshed = auth.api.mcp_o_auth_token(
      body: {
        grant_type: "refresh_token",
        refresh_token: tokens[:refresh_token],
        client_id: client[:client_id]
      }
    )

    refute_equal tokens[:access_token], refreshed[:access_token]
    assert refreshed[:refresh_token]
  end

  def test_resource_request_issues_jwt_access_token
    auth = build_mcp_auth(valid_audiences: ["http://localhost:5000/mcp"])
    cookie = sign_up_cookie(auth)
    client = register_public_mcp_client(auth, scope: "openid offline_access greeting")
    code = authorize_mcp_code(auth, cookie, client, scope: "openid offline_access greeting", resource: "http://localhost:5000/mcp")

    tokens = exchange_mcp_code(auth, client, code, resource: "http://localhost:5000/mcp")
    payload = JWT.decode(tokens[:access_token], MCPTestHelpers::SECRET, true, algorithm: "HS256").first

    assert_equal "http://localhost:5000/mcp", payload["aud"]
    assert_equal "openid offline_access greeting", payload["scope"]
    assert_equal client[:client_id], payload["azp"]
  end
end
```

- [x] **Step 5: Create userinfo tests**

Create `userinfo_test.rb`:

```ruby
# frozen_string_literal: true

require_relative "test_helper"

class BetterAuthPluginsMCPUserinfoTest < Minitest::Test
  include MCPTestHelpers

  def test_userinfo_and_mcp_session_from_access_token
    auth = build_mcp_auth
    cookie = sign_up_cookie(auth)
    client = register_public_mcp_client(auth)
    code = authorize_mcp_code(auth, cookie, client)
    tokens = exchange_mcp_code(auth, client, code)

    userinfo = auth.api.mcp_o_auth_user_info(headers: {"authorization" => "Bearer #{tokens[:access_token]}"})
    session = auth.api.get_mcp_session(headers: {"authorization" => "Bearer #{tokens[:access_token]}"})

    assert_equal "mcp@example.com", userinfo[:email]
    assert_equal client[:client_id], session["clientId"]
    assert session["userId"]
  end
end
```

- [x] **Step 6: Create resource handler tests**

Create `resource_handler_test.rb`:

```ruby
# frozen_string_literal: true

require_relative "test_helper"

class BetterAuthPluginsMCPResourceHandlerTest < Minitest::Test
  include MCPTestHelpers

  def test_with_mcp_auth_returns_www_authenticate_for_missing_bearer_token
    app = BetterAuth::Plugins::MCP.with_mcp_auth(
      ->(_env) { [200, {}, ["ok"]] },
      resource_metadata_url: "http://localhost:5000/.well-known/oauth-protected-resource"
    )

    status, headers, body = app.call({})

    assert_equal 401, status
    assert_equal ["unauthorized"], body
    assert_includes headers.fetch("www-authenticate"), "Bearer"
    assert_includes headers.fetch("www-authenticate"), "resource_metadata=\"http://localhost:5000/.well-known/oauth-protected-resource\""
    assert_equal "WWW-Authenticate", headers.fetch("access-control-expose-headers")
  end

  def test_with_mcp_auth_allows_valid_resource_token
    auth = build_mcp_auth(valid_audiences: ["http://localhost:5000/mcp"])
    cookie = sign_up_cookie(auth)
    client = register_public_mcp_client(auth, scope: "openid offline_access greeting")
    code = authorize_mcp_code(auth, cookie, client, scope: "openid offline_access greeting", resource: "http://localhost:5000/mcp")
    tokens = exchange_mcp_code(auth, client, code, resource: "http://localhost:5000/mcp")

    app = BetterAuth::Plugins::MCP.with_mcp_auth(
      ->(env) { [200, {}, [env.fetch("better_auth.mcp_session").fetch("clientId")]] },
      auth: auth,
      resource_metadata_url: "http://localhost:5000/.well-known/oauth-protected-resource/mcp"
    )

    status, _headers, body = app.call({"HTTP_AUTHORIZATION" => "Bearer #{tokens[:access_token]}"})

    assert_equal 200, status
    assert_equal [client[:client_id]], body
  end
end
```

- [x] **Step 7: Create legacy alias tests**

Create `legacy_aliases_test.rb`:

```ruby
# frozen_string_literal: true

require_relative "test_helper"

class BetterAuthPluginsMCPLegacyAliasesTest < Minitest::Test
  include MCPTestHelpers

  def test_legacy_mcp_routes_delegate_to_canonical_storage
    auth = build_mcp_auth
    cookie = sign_up_cookie(auth)

    client = auth.api.mcp_register(
      body: {
        redirect_uris: ["https://mcp.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Legacy Alias Client",
        scope: "openid offline_access"
      }
    )

    assert auth.context.adapter.find_one(model: "oauthClient", where: [{field: "clientId", value: client[:client_id]}])
    code = authorize_mcp_code(auth, cookie, client, scope: "openid offline_access")
    tokens = exchange_mcp_code(auth, client, code)
    assert tokens[:access_token]
  end
end
```

- [x] **Step 8: Run split tests and verify current failures**

Run:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/metadata_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/registration_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/authorization_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/token_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/userinfo_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/resource_handler_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/legacy_aliases_test.rb
```

Expected before implementation: metadata and registration tests fail because MCP still advertises `/mcp/*` and stores clients in `oauthApplication`.

- [x] **Step 9: Commit the split failing coverage**

```bash
git add packages/better_auth/test/better_auth/plugins/mcp
git commit -m "test: split mcp oauth provider parity coverage"
```

---

### Task 3: Add MCP Config, Metadata, And Schema Modules

**Files:**
- Create: `packages/better_auth/lib/better_auth/plugins/mcp/config.rb`
- Create: `packages/better_auth/lib/better_auth/plugins/mcp/metadata.rb`
- Create: `packages/better_auth/lib/better_auth/plugins/mcp/schema.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- Test: `packages/better_auth/test/better_auth/plugins/mcp/metadata_test.rb`

- [x] **Step 1: Add config module**

Create `config.rb`:

```ruby
# frozen_string_literal: true

require "uri"

module BetterAuth
  module Plugins
    module MCP
      DEFAULT_SCOPES = %w[openid profile email offline_access].freeze
      DEFAULT_GRANT_TYPES = [OAuthProtocol::AUTH_CODE_GRANT, OAuthProtocol::REFRESH_GRANT, OAuthProtocol::CLIENT_CREDENTIALS_GRANT].freeze

      module_function

      def normalize_config(options)
        base = {
          login_page: "/login",
          consent_page: "/oauth2/consent",
          resource: nil,
          scopes: DEFAULT_SCOPES,
          grant_types: DEFAULT_GRANT_TYPES,
          allow_dynamic_client_registration: true,
          allow_unauthenticated_client_registration: true,
          require_pkce: true,
          code_expires_in: 600,
          access_token_expires_in: 3600,
          refresh_token_expires_in: 604_800,
          m2m_access_token_expires_in: 3600,
          store_client_secret: "plain",
          prefix: {},
          store: OAuthProtocol.stores
        }
        BetterAuth::Plugins.normalize_hash(base.merge(BetterAuth::Plugins.normalize_hash(options)))
      end
    end
  end
end
```

- [x] **Step 2: Add metadata module**

Create `metadata.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module_function

      def validate_issuer_url(value)
        uri = URI.parse(value.to_s)
        uri.query = nil
        uri.fragment = nil
        if uri.scheme == "http" && !["localhost", "127.0.0.1", "::1"].include?(uri.hostname || uri.host)
          uri.scheme = "https"
        end
        uri.to_s.sub(%r{/+\z}, "")
      rescue URI::InvalidURIError
        value.to_s.split(/[?#]/).first.sub(%r{/+\z}, "")
      end

      def oauth_metadata(ctx, config)
        base = OAuthProtocol.endpoint_base(ctx)
        {
          issuer: validate_issuer_url(OAuthProtocol.issuer(ctx)),
          authorization_endpoint: "#{base}/oauth2/authorize",
          token_endpoint: "#{base}/oauth2/token",
          userinfo_endpoint: "#{base}/oauth2/userinfo",
          registration_endpoint: "#{base}/oauth2/register",
          introspection_endpoint: "#{base}/oauth2/introspect",
          revocation_endpoint: "#{base}/oauth2/revoke",
          jwks_uri: mcp_jwks_uri(ctx, config),
          scopes_supported: config[:scopes],
          response_types_supported: ["code"],
          response_modes_supported: ["query"],
          grant_types_supported: config[:grant_types],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: mcp_signing_algs(ctx, config),
          token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
          introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: true,
          claims_supported: %w[sub iss aud exp iat sid scope azp email email_verified name picture family_name given_name]
        }
      end

      def protected_resource_metadata(ctx, config)
        base = OAuthProtocol.endpoint_base(ctx)
        origin = OAuthProtocol.origin_for(base)
        resource = config[:resource] || origin
        {
          resource: resource,
          authorization_servers: [origin],
          jwks_uri: mcp_jwks_uri(ctx, config),
          scopes_supported: config[:scopes],
          bearer_methods_supported: ["header"],
          resource_signing_alg_values_supported: mcp_signing_algs(ctx, config)
        }
      end

      def mcp_jwks_uri(ctx, config)
        config.dig(:oidc_config, :metadata, :jwks_uri) ||
          config.dig(:advertised_metadata, :jwks_uri) ||
          "#{OAuthProtocol.endpoint_base(ctx)}/jwks"
      end

      def mcp_signing_algs(ctx, config)
        jwt_plugin = ctx.context.options.plugins.find { |plugin| plugin.id == "jwt" }
        alg = config.dig(:jwt, :jwks, :key_pair_config, :alg) ||
          jwt_plugin&.options&.dig(:jwks, :key_pair_config, :alg)
        [alg || "EdDSA"]
      end
    end
  end
end
```

- [x] **Step 3: Add schema module**

Create `schema.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module_function

      def schema
        {
          oauthClient: {
            modelName: "oauthClient",
            fields: {
              clientId: {type: "string", unique: true, required: true},
              clientSecret: {type: "string", required: false},
              disabled: {type: "boolean", default_value: false, required: false},
              skipConsent: {type: "boolean", required: false},
              enableEndSession: {type: "boolean", required: false},
              clientSecretExpiresAt: {type: "number", required: false},
              scopes: {type: "string[]", required: false},
              userId: {type: "string", required: false},
              createdAt: {type: "date", required: true, default_value: -> { Time.now }},
              updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }},
              name: {type: "string", required: false},
              uri: {type: "string", required: false},
              icon: {type: "string", required: false},
              contacts: {type: "string[]", required: false},
              tos: {type: "string", required: false},
              policy: {type: "string", required: false},
              softwareId: {type: "string", required: false},
              softwareVersion: {type: "string", required: false},
              softwareStatement: {type: "string", required: false},
              redirectUris: {type: "string[]", required: true},
              postLogoutRedirectUris: {type: "string[]", required: false},
              tokenEndpointAuthMethod: {type: "string", required: false},
              grantTypes: {type: "string[]", required: false},
              responseTypes: {type: "string[]", required: false},
              public: {type: "boolean", required: false},
              type: {type: "string", required: false},
              requirePKCE: {type: "boolean", required: false},
              subjectType: {type: "string", required: false},
              referenceId: {type: "string", required: false},
              metadata: {type: "json", required: false}
            }
          },
          oauthRefreshToken: {
            fields: {
              token: {type: "string", required: true},
              clientId: {type: "string", required: true},
              sessionId: {type: "string", required: false},
              userId: {type: "string", required: false},
              referenceId: {type: "string", required: false},
              authTime: {type: "date", required: false},
              expiresAt: {type: "date", required: false},
              createdAt: {type: "date", required: true, default_value: -> { Time.now }},
              revoked: {type: "date", required: false},
              scopes: {type: "string[]", required: true}
            }
          },
          oauthAccessToken: {
            modelName: "oauthAccessToken",
            fields: {
              token: {type: "string", unique: true, required: true},
              expiresAt: {type: "date", required: true},
              clientId: {type: "string", required: true},
              userId: {type: "string", required: false},
              sessionId: {type: "string", required: false},
              scopes: {type: "string[]", required: true},
              revoked: {type: "date", required: false},
              referenceId: {type: "string", required: false},
              authTime: {type: "date", required: false},
              refreshId: {type: "string", required: false},
              createdAt: {type: "date", required: true, default_value: -> { Time.now }},
              updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }}
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
        }
      end
    end
  end
end
```

- [x] **Step 4: Wire config, metadata, and schema into the plugin**

In `mcp.rb`, replace the inline defaults and metadata body with module calls:

```ruby
require_relative "mcp/config"
require_relative "mcp/metadata"
require_relative "mcp/schema"

module BetterAuth
  module Plugins
    module MCP
      module_function

      def with_mcp_auth(app, resource_metadata_url:, auth: nil)
        ResourceHandler.with_mcp_auth(app, resource_metadata_url: resource_metadata_url, auth: auth)
      end
    end

    module_function

    def mcp(options = {})
      config = MCP.normalize_config(options)
      Plugin.new(
        id: "mcp",
        endpoints: mcp_endpoints(config),
        hooks: {after: [{matcher: ->(_ctx) { true }, handler: ->(ctx) { mcp_restore_login_prompt(ctx, config) }}]},
        schema: MCP.schema,
        options: config
      )
    end

    def mcp_oauth_config_endpoint(config)
      Endpoint.new(path: "/.well-known/oauth-authorization-server", method: "GET", metadata: {hide: true}) do |ctx|
        ctx.json(MCP.oauth_metadata(ctx, config))
      end
    end

    def mcp_protected_resource_endpoint(config)
      Endpoint.new(path: "/.well-known/oauth-protected-resource", method: "GET", metadata: {hide: true}) do |ctx|
        ctx.json(MCP.protected_resource_metadata(ctx, config))
      end
    end
  end
end
```

- [x] **Step 5: Run metadata tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/metadata_test.rb
```

Expected: metadata tests pass and no `oauthApplication` schema is introduced by MCP.

- [x] **Step 6: Commit metadata modernization**

```bash
git add packages/better_auth/lib/better_auth/plugins/mcp.rb packages/better_auth/lib/better_auth/plugins/mcp/config.rb packages/better_auth/lib/better_auth/plugins/mcp/metadata.rb packages/better_auth/lib/better_auth/plugins/mcp/schema.rb
git commit -m "feat: add oauth provider metadata for mcp"
```

---

### Task 4: Move MCP Registration To `oauthClient`

**Files:**
- Create: `packages/better_auth/lib/better_auth/plugins/mcp/registration.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- Test: `packages/better_auth/test/better_auth/plugins/mcp/registration_test.rb`

- [x] **Step 1: Add registration module**

Create `registration.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module_function

      def register_client(ctx, config)
        set_cors_headers(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        body["token_endpoint_auth_method"] ||= "none"
        body["grant_types"] ||= [OAuthProtocol::AUTH_CODE_GRANT, OAuthProtocol::REFRESH_GRANT]
        body["response_types"] ||= ["code"]
        body["require_pkce"] = true unless body.key?("require_pkce") || body.key?("requirePKCE")

        OAuthProtocol.create_client(
          ctx,
          model: "oauthClient",
          body: body,
          default_auth_method: "none",
          store_client_secret: config[:store_client_secret],
          unauthenticated: true,
          default_scopes: config[:scopes],
          allowed_scopes: config[:scopes],
          dynamic_registration: true,
          strip_client_metadata: true
        )
      end

      def set_cors_headers(ctx)
        ctx.set_header("access-control-allow-origin", "*")
        ctx.set_header("access-control-allow-methods", "POST, OPTIONS")
        ctx.set_header("access-control-allow-headers", "Content-Type, Authorization")
        ctx.set_header("access-control-max-age", "86400")
      end
    end
  end
end
```

- [x] **Step 2: Wire registration endpoint**

In `mcp.rb`, require the module and change `mcp_register_endpoint`:

```ruby
require_relative "mcp/registration"

def mcp_register_endpoint(config)
  Endpoint.new(path: "/oauth2/register", method: "POST", metadata: mcp_openapi("registerMcpClient", "Register an OAuth2 application", "OAuth2 application registered successfully", mcp_client_schema)) do |ctx|
    ctx.json(MCP.register_client(ctx, config), status: 201, headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"})
  end
end
```

- [x] **Step 3: Keep legacy registration alias**

Add an alias endpoint in the endpoint map:

```ruby
legacy_mcp_register: Endpoint.new(path: "/mcp/register", method: "POST", metadata: mcp_openapi("registerMcpClientLegacy", "Register an OAuth2 application using the legacy MCP path", "OAuth2 application registered successfully", mcp_client_schema)) do |ctx|
  ctx.json(MCP.register_client(ctx, config), status: 201, headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"})
end
```

- [x] **Step 4: Run registration and legacy tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/registration_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/legacy_aliases_test.rb
```

Expected: registration stores clients in `oauthClient`; legacy `/mcp/register` still works through `auth.api.mcp_register`.

- [x] **Step 5: Commit registration migration**

```bash
git add packages/better_auth/lib/better_auth/plugins/mcp.rb packages/better_auth/lib/better_auth/plugins/mcp/registration.rb packages/better_auth/test/better_auth/plugins/mcp/registration_test.rb packages/better_auth/test/better_auth/plugins/mcp/legacy_aliases_test.rb
git commit -m "feat: register mcp clients as oauth clients"
```

---

### Task 5: Modularize Authorization And Login Prompt Restore

**Files:**
- Create: `packages/better_auth/lib/better_auth/plugins/mcp/authorization.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- Test: `packages/better_auth/test/better_auth/plugins/mcp/authorization_test.rb`

- [x] **Step 1: Add authorization module**

Create `authorization.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module_function

      def authorize(ctx, config)
        set_cors_headers(ctx)
        query = OAuthProtocol.stringify_keys(ctx.query)
        session = Routes.current_session(ctx, allow_nil: true)
        unless session
          ctx.set_signed_cookie("oidc_login_prompt", JSON.generate(query), ctx.context.secret, max_age: 600, path: "/", same_site: "lax")
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(config[:login_page], query))
        end

        client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
        return redirect_error(ctx, ctx.context.base_url + "/error", "invalid_client") unless client
        client_data = OAuthProtocol.stringify_keys(client)
        return redirect_error(ctx, ctx.context.base_url + "/error", "client_disabled") if client_data["disabled"]
        return redirect_error(ctx, ctx.context.base_url + "/error", "unsupported_response_type") unless query["response_type"] == "code"

        OAuthProtocol.validate_redirect_uri!(client, query["redirect_uri"])
        scopes = OAuthProtocol.parse_scopes(query["scope"] || "openid")
        invalid_scopes = scopes.reject { |scope| config[:scopes].include?(scope) }
        unless invalid_scopes.empty?
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "invalid_scope", error_description: "The following scopes are invalid: #{invalid_scopes.join(", ")}", state: query["state"]))
        end

        if config[:require_pkce] && (query["code_challenge"].to_s.empty? || query["code_challenge_method"].to_s.empty?)
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "invalid_request", error_description: "pkce is required", state: query["state"]))
        end

        unless query["code_challenge_method"].to_s.casecmp("S256").zero?
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "invalid_request", error_description: "invalid code_challenge method", state: query["state"]))
        end

        if query["prompt"].to_s.split(/\s+/).include?("consent")
          consent_code = Crypto.random_string(32)
          config[:store][:consents][consent_code] = {query: query, session: session, client: client, scopes: scopes, expires_at: Time.now + config[:code_expires_in].to_i}
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(config[:consent_page], consent_code: consent_code, client_id: client_data["clientId"], scope: OAuthProtocol.scope_string(scopes)))
        end

        redirect_with_code(ctx, config, query, session, client, scopes)
      end

      def redirect_with_code(ctx, config, query, session, client, scopes)
        raise ctx.redirect(authorization_redirect_uri(ctx, config, query, session, client, scopes))
      end

      def authorization_redirect_uri(ctx, config, query, session, client, scopes)
        code = Crypto.random_string(32)
        OAuthProtocol.store_code(
          config[:store],
          code: code,
          client_id: query["client_id"],
          redirect_uri: query["redirect_uri"],
          session: session,
          scopes: scopes,
          code_challenge: query["code_challenge"],
          code_challenge_method: query["code_challenge_method"],
          nonce: query["nonce"],
          reference_id: OAuthProtocol.stringify_keys(client)["referenceId"]
        )
        OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], code: code, state: query["state"], iss: validate_issuer_url(OAuthProtocol.issuer(ctx)))
      end

      def restore_login_prompt(ctx, config)
        cookie = ctx.get_signed_cookie("oidc_login_prompt", ctx.context.secret)
        return unless cookie
        session = ctx.context.new_session
        return unless session && session[:session] && ctx.response_headers["set-cookie"].to_s.include?(ctx.context.auth_cookies[:session_token].name)
        query = JSON.parse(cookie)
        query["prompt"] = query["prompt"].to_s.split(/\s+/).reject { |prompt| prompt == "login" }.join(" ")
        ctx.set_cookie("oidc_login_prompt", "", path: "/", max_age: 0)
        ctx.context.set_current_session(session) if ctx.context.respond_to?(:set_current_session)
        client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
        return unless client
        scopes = OAuthProtocol.parse_scopes(query["scope"] || "openid")
        location = authorization_redirect_uri(ctx, config, query, session, client, scopes)
        [302, ctx.response_headers.merge("location" => location), [""]]
      rescue JSON::ParserError
        nil
      end

      def redirect_error(ctx, redirect_uri, error)
        raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(redirect_uri, error: error))
      end
    end
  end
end
```

- [x] **Step 2: Wire authorization endpoints**

In `mcp.rb`, require `authorization.rb`, update the hook, and map both canonical and legacy authorize endpoints:

```ruby
require_relative "mcp/authorization"

def mcp_endpoints(config)
  {
    get_mcp_o_auth_config: mcp_oauth_config_endpoint(config),
    get_mcp_protected_resource: mcp_protected_resource_endpoint(config),
    mcp_register: mcp_register_endpoint(config),
    mcp_o_auth_authorize: Endpoint.new(path: "/oauth2/authorize", method: "GET", metadata: mcp_openapi("mcpOAuthAuthorize", "Authorize an OAuth2 request using MCP", "Authorization response generated successfully", {type: "object", additionalProperties: true})) { |ctx| MCP.authorize(ctx, config) },
    legacy_mcp_o_auth_authorize: Endpoint.new(path: "/mcp/authorize", method: "GET", metadata: mcp_openapi("mcpOAuthAuthorizeLegacy", "Authorize an OAuth2 request using the legacy MCP path", "Authorization response generated successfully", {type: "object", additionalProperties: true})) { |ctx| MCP.authorize(ctx, config) }
  }
end
```

- [x] **Step 3: Run authorization tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/authorization_test.rb
```

Expected: authorize returns codes for valid PKCE requests and redirects with OAuth errors for invalid scope and missing PKCE.

- [x] **Step 4: Commit authorization split**

```bash
git add packages/better_auth/lib/better_auth/plugins/mcp.rb packages/better_auth/lib/better_auth/plugins/mcp/authorization.rb packages/better_auth/test/better_auth/plugins/mcp/authorization_test.rb
git commit -m "feat: modularize mcp authorization"
```

---

### Task 6: Modularize Token, Refresh, Userinfo, And Session

**Files:**
- Create: `packages/better_auth/lib/better_auth/plugins/mcp/token.rb`
- Create: `packages/better_auth/lib/better_auth/plugins/mcp/userinfo.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- Test: `packages/better_auth/test/better_auth/plugins/mcp/token_test.rb`
- Test: `packages/better_auth/test/better_auth/plugins/mcp/userinfo_test.rb`

- [x] **Step 1: Add token module**

Create `token.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module_function

      def token(ctx, config)
        set_cors_headers(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.authenticate_client!(ctx, "oauthClient", store_client_secret: config[:store_client_secret], prefix: config[:prefix])
        audience = validate_resource!(config, body)

        case body["grant_type"]
        when OAuthProtocol::AUTH_CODE_GRANT
          code = OAuthProtocol.consume_code!(
            config[:store],
            body["code"],
            client_id: body["client_id"],
            redirect_uri: body["redirect_uri"],
            code_verifier: body["code_verifier"]
          )
          OAuthProtocol.issue_tokens(
            ctx,
            config[:store],
            model: "oauthAccessToken",
            client: client,
            session: code[:session],
            scopes: code[:scopes],
            include_refresh: code[:scopes].include?("offline_access"),
            issuer: validate_issuer_url(OAuthProtocol.issuer(ctx)),
            prefix: config[:prefix],
            refresh_token_expires_in: config[:refresh_token_expires_in],
            access_token_expires_in: config[:access_token_expires_in],
            audience: audience,
            grant_type: OAuthProtocol::AUTH_CODE_GRANT,
            jwt_access_token: !audience.nil?,
            filter_id_token_claims_by_scope: true
          )
        when OAuthProtocol::REFRESH_GRANT
          OAuthProtocol.refresh_tokens(
            ctx,
            config[:store],
            model: "oauthAccessToken",
            client: client,
            refresh_token: body["refresh_token"],
            scopes: body["scope"],
            issuer: validate_issuer_url(OAuthProtocol.issuer(ctx)),
            prefix: config[:prefix],
            refresh_token_expires_in: config[:refresh_token_expires_in],
            audience: audience,
            jwt_access_token: !audience.nil?,
            filter_id_token_claims_by_scope: true
          )
        else
          raise APIError.new("BAD_REQUEST", message: "unsupported_grant_type")
        end
      end

      def validate_resource!(config, body)
        resources = Array(body["resource"]).compact.map(&:to_s)
        return nil if resources.empty?
        valid = Array(config[:valid_audiences]).map(&:to_s)
        resources.each do |resource|
          raise APIError.new("BAD_REQUEST", message: "requested resource invalid") unless valid.empty? || valid.include?(resource)
        end
        resources.length == 1 ? resources.first : resources
      end
    end
  end
end
```

- [x] **Step 2: Add userinfo module**

Create `userinfo.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module_function

      def userinfo(ctx, config)
        OAuthProtocol.userinfo(config[:store], ctx.headers["authorization"], prefix: config[:prefix], jwt_secret: ctx.context.secret)
      end

      def session_from_token(ctx, config)
        authorization = ctx.headers["authorization"].to_s
        token_value = authorization.start_with?("Bearer ") ? authorization.delete_prefix("Bearer ") : authorization
        token = OAuthProtocol.find_token_by_hint(config[:store], token_value, "access_token", prefix: config[:prefix])
        return token if token && !token["revoked"]

        jwt = BetterAuth::Plugins.oauth_introspect_jwt_access_token(ctx, {"clientId" => nil}, token_value) if BetterAuth::Plugins.respond_to?(:oauth_introspect_jwt_access_token)
        jwt && jwt[:active] ? {"clientId" => jwt[:client_id], "userId" => jwt[:sub], "scopes" => jwt[:scope], "audience" => jwt[:aud]} : nil
      end
    end
  end
end
```

- [x] **Step 3: Wire token and userinfo endpoints**

In `mcp.rb`, require the modules and add canonical plus legacy endpoints:

```ruby
require_relative "mcp/token"
require_relative "mcp/userinfo"

o_auth2_token: Endpoint.new(path: "/oauth2/token", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
  ctx.json(MCP.token(ctx, config))
end,
legacy_mcp_o_auth_token: Endpoint.new(path: "/mcp/token", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
  ctx.json(MCP.token(ctx, config))
end,
o_auth2_user_info: Endpoint.new(path: "/oauth2/userinfo", method: "GET") do |ctx|
  ctx.json(MCP.userinfo(ctx, config))
end,
legacy_mcp_o_auth_user_info: Endpoint.new(path: "/mcp/userinfo", method: "GET") do |ctx|
  ctx.json(MCP.userinfo(ctx, config))
end,
get_mcp_session: Endpoint.new(path: "/mcp/get-session", method: "GET") do |ctx|
  ctx.json(MCP.session_from_token(ctx, config))
end
```

- [x] **Step 4: Run token and userinfo tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/token_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/userinfo_test.rb
```

Expected: authorization-code exchange, refresh, JWT resource tokens, userinfo, and session lookup pass.

- [x] **Step 5: Commit token and userinfo migration**

```bash
git add packages/better_auth/lib/better_auth/plugins/mcp.rb packages/better_auth/lib/better_auth/plugins/mcp/token.rb packages/better_auth/lib/better_auth/plugins/mcp/userinfo.rb packages/better_auth/test/better_auth/plugins/mcp/token_test.rb packages/better_auth/test/better_auth/plugins/mcp/userinfo_test.rb
git commit -m "feat: issue oauth provider tokens for mcp"
```

---

### Task 7: Add MCP Resource Handler Module

**Files:**
- Create: `packages/better_auth/lib/better_auth/plugins/mcp/resource_handler.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- Test: `packages/better_auth/test/better_auth/plugins/mcp/resource_handler_test.rb`

- [x] **Step 1: Add resource handler module**

Create `resource_handler.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module ResourceHandler
        module_function

        def with_mcp_auth(app, resource_metadata_url:, auth: nil, resource_metadata_mappings: {})
          lambda do |env|
            authorization = env["HTTP_AUTHORIZATION"].to_s
            return unauthorized(resource_metadata_url) unless authorization.start_with?("Bearer ")

            session = auth&.api&.get_mcp_session(headers: {"authorization" => authorization})
            return unauthorized(resource_metadata_url) unless session

            env["better_auth.mcp_session"] = session
            app.call(env)
          rescue APIError
            unauthorized(resource_metadata_url)
          end
        end

        def unauthorized(resource_metadata_url)
          [
            401,
            {
              "www-authenticate" => %(Bearer resource_metadata="#{resource_metadata_url}"),
              "access-control-expose-headers" => "WWW-Authenticate"
            },
            ["unauthorized"]
          ]
        end
      end
    end
  end
end
```

- [x] **Step 2: Wire public API to resource handler**

In `mcp.rb`, require `resource_handler.rb` and delegate:

```ruby
require_relative "mcp/resource_handler"

module BetterAuth
  module Plugins
    module MCP
      module_function

      def with_mcp_auth(app, resource_metadata_url:, auth: nil, resource_metadata_mappings: {})
        ResourceHandler.with_mcp_auth(
          app,
          resource_metadata_url: resource_metadata_url,
          auth: auth,
          resource_metadata_mappings: resource_metadata_mappings
        )
      end
    end
  end
end
```

- [x] **Step 3: Run resource handler tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/resource_handler_test.rb
```

Expected: missing bearer tokens return `401` with `WWW-Authenticate`; valid resource tokens pass session data into Rack env.

- [x] **Step 4: Commit resource handler**

```bash
git add packages/better_auth/lib/better_auth/plugins/mcp.rb packages/better_auth/lib/better_auth/plugins/mcp/resource_handler.rb packages/better_auth/test/better_auth/plugins/mcp/resource_handler_test.rb
git commit -m "feat: add mcp oauth resource handler"
```

---

### Task 8: Thin Out `mcp.rb` And Remove Monolithic Test

**Files:**
- Modify: `packages/better_auth/lib/better_auth/plugins/mcp.rb`
- Delete: `packages/better_auth/test/better_auth/plugins/mcp_test.rb`
- Test: all `packages/better_auth/test/better_auth/plugins/mcp/*_test.rb`

- [x] **Step 1: Replace `mcp.rb` with loader and endpoint assembler only**

Keep `mcp.rb` focused on requires, the public `mcp` method, endpoint map, and OpenAPI schema helpers:

```ruby
# frozen_string_literal: true

require "json"
require_relative "mcp/config"
require_relative "mcp/metadata"
require_relative "mcp/schema"
require_relative "mcp/registration"
require_relative "mcp/authorization"
require_relative "mcp/token"
require_relative "mcp/userinfo"
require_relative "mcp/resource_handler"
require_relative "mcp/legacy_aliases"

module BetterAuth
  module Plugins
    module_function

    def mcp(options = {})
      config = MCP.normalize_config(options)
      Plugin.new(
        id: "mcp",
        endpoints: mcp_endpoints(config),
        hooks: {after: [{matcher: ->(_ctx) { true }, handler: ->(ctx) { MCP.restore_login_prompt(ctx, config) }}]},
        schema: MCP.schema,
        options: config
      )
    end
  end
end
```

- [x] **Step 2: Delete the old monolithic test file**

Run:

```bash
git rm packages/better_auth/test/better_auth/plugins/mcp_test.rb
```

- [x] **Step 3: Run split MCP test suite**

Run:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/metadata_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/registration_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/authorization_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/token_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/userinfo_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/resource_handler_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/legacy_aliases_test.rb
```

Expected: every split MCP test passes.

- [x] **Step 4: Commit modular MCP structure**

```bash
git add packages/better_auth/lib/better_auth/plugins/mcp.rb packages/better_auth/lib/better_auth/plugins/mcp packages/better_auth/test/better_auth/plugins/mcp
git commit -m "refactor: modularize mcp oauth provider implementation"
```

---

### Task 9: Full Regression And Documentation Check

**Files:**
- Modify: `packages/better_auth/CHANGELOG.md` if this repository expects package changelog entries for unreleased behavior.
- Modify: `README.md` only if MCP usage examples currently mention `/mcp/*` as the primary route.
- Test: core BetterAuth and OAuth provider package suites.

- [x] **Step 1: Run core plugin tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/metadata_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/registration_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/authorization_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/token_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/userinfo_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/resource_handler_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/mcp/legacy_aliases_test.rb
```

Expected: all MCP tests pass.

- [x] **Step 2: Run the core package test suite**

Run from `packages/better_auth`:

```bash
rbenv exec bundle exec rake test
```

Expected: all core package tests pass.

- [x] **Step 3: Run OAuth provider package test suite**

Run from `packages/better_auth-oauth-provider`:

```bash
rbenv exec bundle exec rake test
```

Expected: OAuth provider suite stays green; MCP changes did not regress shared `OAuthProtocol`.

- [x] **Step 4: Run StandardRB for touched packages**

Run from repository root:

```bash
rbenv exec bundle exec standardrb packages/better_auth/lib/better_auth/plugins/mcp.rb packages/better_auth/lib/better_auth/plugins/mcp packages/better_auth/test/better_auth/plugins/mcp
```

Expected: no formatting or lint offenses.

- [x] **Step 5: Add changelog note if required**

If `packages/better_auth/CHANGELOG.md` exists, add:

```markdown
- Modernized the MCP plugin to use OAuth Provider-style client, token, metadata, and protected-resource behavior while keeping legacy MCP routes as aliases.
```

- [x] **Step 6: Final commit**

```bash
git add packages/better_auth packages/better_auth-oauth-provider README.md
git commit -m "feat: modernize mcp oauth provider flow"
```

---

## Self-Review

- Spec coverage: This plan covers replacing MCP internals with OAuth Provider-style behavior, preserving tests, splitting tests into multiple files, and modularizing implementation files instead of extending the current monolith.
- Upstream alignment: The plan uses `upstream/packages/better-auth/src/plugins/mcp/*` for current MCP behavior and `upstream/packages/oauth-provider/src/mcp.ts` plus OAuth Provider tests for the modern resource-handler direction.
- Ruby adaptation: Because `better_auth-oauth-provider` is a separate gem, the core MCP plugin should share `OAuthProtocol` primitives and canonical OAuth Provider schema instead of requiring the external gem from core.
- Test shape: New tests are split by metadata, registration, authorization, token, userinfo, resource handler, and legacy aliases. The old single `mcp_test.rb` is removed only after split coverage passes.

## Implementation Notes

- Ruby adaptation: the per-task commit checkpoints were batched into one MCP implementation change to keep this dirty worktree easier to review.
- Ruby adaptation: MCP no longer calls `oidc_provider`, `OIDCProvider`, `oidc_provider_schema`, or `oauthApplication`; it uses `OAuthProtocol` with canonical `oauthClient`, `oauthAccessToken`, `oauthRefreshToken`, and `oauthConsent` storage.
- Ruby adaptation: resource-token tests explicitly configure the custom `greeting` scope before registering clients that request it.
- Verification: split MCP tests pass with 16 runs and 97 assertions; full `packages/better_auth` passes with 820 runs and 4329 assertions; full `packages/better_auth-oauth-provider` passes with 125 runs and 677 assertions; StandardRB for touched MCP Ruby files passes.
