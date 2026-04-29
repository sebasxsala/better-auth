# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "rack/mock"
require_relative "../test_helper"

class BetterAuthPluginsOAuthProviderTest < Minitest::Test
  SECRET = "phase-eleven-secret-with-enough-entropy-123"

  def test_validate_issuer_url_matches_rfc_9207_upstream_behavior
    assert_equal "https://issuer.example.com", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("https://issuer.example.com/")
    assert_equal "https://issuer.example.com/auth", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://issuer.example.com/auth?x=1#frag")
    assert_equal "http://localhost:3000", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://localhost:3000/")
    assert_equal "http://127.0.0.1:3000", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://127.0.0.1:3000/")
  end

  def test_schema_is_self_contained_and_does_not_register_core_oidc_application_table
    auth = build_auth
    schema = BetterAuth::Schema.auth_tables(auth.options)

    assert schema.key?("oauthClient")
    assert schema.key?("oauthAccessToken")
    assert schema.key?("oauthRefreshToken")
    assert schema.key?("oauthConsent")
    refute schema.key?("oauthApplication")
  end

  def test_plugin_exposes_upstream_rate_limit_rules
    plugin = BetterAuth::Plugins.oauth_provider(
      rate_limit: {
        token: {window: 15, max: 2},
        userinfo: false
      }
    )

    rules = plugin.rate_limit
    paths = rules.map { |rule| oauth_rate_limit_path(rule) }

    assert_equal [
      "/oauth2/token",
      "/oauth2/authorize",
      "/oauth2/introspect",
      "/oauth2/revoke",
      "/oauth2/register"
    ], paths
    token_rule = rules.fetch(0)
    assert_equal 15, token_rule[:window]
    assert_equal 2, token_rule[:max]
    assert_equal({window: 60, max: 30}, rules.fetch(1).slice(:window, :max))
    assert_equal({window: 60, max: 100}, rules.fetch(2).slice(:window, :max))
    assert_equal({window: 60, max: 30}, rules.fetch(3).slice(:window, :max))
    assert_equal({window: 60, max: 5}, rules.fetch(4).slice(:window, :max))
  end

  def test_metadata_client_management_introspection_and_revocation
    auth = build_auth
    cookie = sign_up_cookie(auth)

    metadata = auth.api.get_o_auth_server_config
    assert_equal "http://localhost:3000", metadata[:issuer]
    assert_equal "http://localhost:3000/api/auth/oauth2/introspect", metadata[:introspection_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/revoke", metadata[:revocation_endpoint]
    assert_includes metadata[:grant_types_supported], "client_credentials"

    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Machine Client",
        scope: "read write"
      }
    )
    assert client[:client_id]
    assert client[:client_secret]

    public_client = auth.api.get_o_auth_client_public(query: {client_id: client[:client_id]})
    assert_equal "Machine Client", public_client[:client_name]
    assert_nil public_client[:client_secret]

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read"
      }
    )
    assert_equal "Bearer", tokens[:token_type]
    assert tokens[:access_token]
    assert_equal "read", tokens[:scope]

    active = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal true, active[:active]
    assert_equal client[:client_id], active[:client_id]
    assert_equal "read", active[:scope]

    revoke = auth.api.o_auth2_revoke(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal({revoked: true}, revoke)

    inactive = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal false, inactive[:active]
  end

  def test_dynamic_registration_requires_explicit_enablement
    auth = build_auth(allow_dynamic_client_registration: false)
    cookie = sign_up_cookie(auth)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.register_o_auth_client(
        headers: {"cookie" => cookie},
        body: {
          redirect_uris: ["https://resource.example/callback"],
          token_endpoint_auth_method: "none",
          client_name: "Public Client"
        }
      )
    end

    assert_equal 403, error.status_code
  end

  def test_unauthenticated_dynamic_registration_is_coerced_to_public_client
    auth = build_auth(
      scopes: ["openid", "profile", "email", "offline_access"],
      allow_unauthenticated_client_registration: true,
      client_registration_default_scopes: ["openid", "profile"],
      client_registration_allowed_scopes: ["openid", "profile", "email"],
      store_client_secret: "hashed"
    )

    status, headers, body = auth.api.register_o_auth_client(
      body: {
        client_id: "attacker-controlled-id",
        client_secret: "attacker-controlled-secret",
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Public Browser Client",
        scope: "openid email",
        type: "web",
        metadata: {software_id: "client-kit"},
        tos_uri: "https://resource.example/terms"
      },
      as_response: true
    )

    assert_equal 201, status
    assert_equal "no-store", headers.fetch("cache-control")
    assert_equal "no-cache", headers.fetch("pragma")
    client = JSON.parse(body.join, symbolize_names: true)
    refute_equal "attacker-controlled-id", client[:client_id]
    assert_nil client[:client_secret]
    refute client.key?(:client_secret_expires_at)
    assert_equal "none", client[:token_endpoint_auth_method]
    assert_equal true, client[:public]
    assert_nil client[:user_id]
    assert_nil client[:type]
    assert_equal "openid email", client[:scope]
    assert_equal "client-kit", client[:software_id]
    assert_equal "https://resource.example/terms", client[:tos_uri]
    refute client.key?(:skip_consent)
  end

  def test_dynamic_registration_omitted_scope_uses_provider_scopes
    auth = build_auth(scopes: ["openid", "profile"], allow_unauthenticated_client_registration: true)

    client = auth.api.register_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Default Scope Client"
      }
    )

    assert_equal "openid profile", client[:scope]
  end

  def test_dynamic_registration_rejects_skip_consent
    auth = build_auth(allow_unauthenticated_client_registration: true)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.register_o_auth_client(
        body: {
          redirect_uris: ["https://resource.example/callback"],
          token_endpoint_auth_method: "none",
          grant_types: ["authorization_code"],
          response_types: ["code"],
          skip_consent: true
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/skip_consent/i, error.message)
  end

  def test_unauthenticated_dynamic_registration_rejects_confidential_grants
    auth = build_auth(allow_unauthenticated_client_registration: true)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.register_o_auth_client(
        body: {
          redirect_uris: ["https://resource.example/callback"],
          token_endpoint_auth_method: "none",
          grant_types: ["client_credentials"],
          response_types: []
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/public/i, error.message)
  end

  def test_dynamic_registration_rejects_invalid_client_metadata_enums
    auth = build_auth(allow_unauthenticated_client_registration: true)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.register_o_auth_client(
        body: {
          redirect_uris: ["https://resource.example/callback"],
          token_endpoint_auth_method: "private_key_jwt",
          grant_types: ["authorization_code"],
          response_types: ["code"]
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/token_endpoint_auth_method/i, error.message)
  end

  def test_authorization_code_flow_requires_and_records_consent
    auth = build_auth(consent_page: "/consent")
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Browser Client",
        scope: "read write"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "state-123",
        prompt: "consent",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    consent_redirect = URI.parse(headers.fetch("location"))
    assert_equal "/consent", consent_redirect.path
    consent_code = Rack::Utils.parse_query(consent_redirect.query).fetch("consent_code")

    consent = auth.api.o_auth2_consent(
      headers: {"cookie" => cookie},
      body: {accept: true, consent_code: consent_code}
    )
    callback = URI.parse(consent.fetch(:redirectURI))
    params = Rack::Utils.parse_query(callback.query)
    assert_equal "state-123", params.fetch("state")
    assert_equal "http://localhost:3000", params.fetch("iss")
    assert params.fetch("code")

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: params.fetch("code"),
        redirect_uri: "https://resource.example/callback",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        code_verifier: pkce_verifier
      }
    )
    assert_equal "Bearer", tokens[:token_type]
    assert_equal "read", tokens[:scope]
    assert tokens[:refresh_token]

    consent_record = auth.context.adapter.find_one(model: "oauthConsent", where: [{field: "clientId", value: client[:client_id]}])
    assert_equal true, consent_record.fetch("consentGiven")
  end

  def test_consent_can_grant_narrower_scope_set
    auth = build_auth(scopes: ["read", "write"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Narrow Consent Client",
        scope: "read write"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read write",
        state: "narrow-state",
        prompt: "consent",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    consent_code = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query).fetch("consent_code")

    consent = auth.api.o_auth2_consent(
      headers: {"cookie" => cookie},
      body: {accept: true, consent_code: consent_code, scope: "read"}
    )
    code = Rack::Utils.parse_query(URI.parse(consent.fetch(:redirectURI)).query).fetch("code")
    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "https://resource.example/callback",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        code_verifier: pkce_verifier
      }
    )

    assert_equal "read", tokens[:scope]
    saved = auth.api.get_o_auth_consent(headers: {"cookie" => cookie}, query: {client_id: client[:client_id]})
    assert_equal ["read"], saved[:scopes]
  end

  def test_continue_created_reenters_authorize_from_signed_oauth_query
    auth = build_auth(signup: {page: "/signup"}, consent_page: "/consent")
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Continue Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "continue-state",
        prompt: "create consent",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    signup_uri = URI.parse(headers.fetch("location"))
    assert_equal "/signup", signup_uri.path
    signup_params = Rack::Utils.parse_query(signup_uri.query)
    assert signup_params["sig"]
    assert signup_params["exp"]

    continued = auth.api.o_auth2_continue(
      headers: {"cookie" => cookie},
      body: {created: true, oauth_query: signup_uri.query}
    )

    assert_equal true, continued[:redirect]
    redirect_uri = URI.parse(continued[:url])
    assert_equal "/consent", redirect_uri.path
    assert_equal client[:client_id], Rack::Utils.parse_query(redirect_uri.query).fetch("client_id")
  end

  def test_continue_selected_reenters_authorize_and_issues_code
    auth = build_auth(select_account: {page: "/select-account"})
    cookie = sign_up_cookie(auth)
    client = auth.api.create_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Select Account Client",
        scope: "read",
        skip_consent: true
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "select-state",
        prompt: "select_account",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    select_uri = URI.parse(headers.fetch("location"))
    assert_equal "/select-account", select_uri.path

    continued = auth.api.o_auth2_continue(
      headers: {"cookie" => cookie},
      body: {selected: true, oauth_query: select_uri.query}
    )

    callback = URI.parse(continued[:url])
    params = Rack::Utils.parse_query(callback.query)
    assert_equal "select-state", params.fetch("state")
    assert params.fetch("code")
  end

  def test_continue_post_login_reenters_authorize_and_issues_code
    auth = build_auth(
      post_login: {
        page: "/post-login",
        should_redirect: ->(_info) { true }
      }
    )
    cookie = sign_up_cookie(auth)
    client = auth.api.create_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Post Login Client",
        scope: "read",
        skip_consent: true
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "post-login-state",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    post_login_uri = URI.parse(headers.fetch("location"))
    assert_equal "/post-login", post_login_uri.path

    continued = auth.api.o_auth2_continue(
      headers: {"cookie" => cookie},
      body: {postLogin: true, oauth_query: post_login_uri.query}
    )

    callback = URI.parse(continued[:url])
    params = Rack::Utils.parse_query(callback.query)
    assert_equal "post-login-state", params.fetch("state")
    assert params.fetch("code")
  end

  def test_authorize_requires_pkce_by_default
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Public Browser Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "state-pkce"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "invalid_request", params.fetch("error")
    assert_match(/pkce/i, params.fetch("error_description"))
    assert_equal "state-pkce", params.fetch("state")
  end

  def test_confidential_authorize_requires_pkce_by_default
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Confidential Browser Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "state-confidential-pkce"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "invalid_request", params.fetch("error")
    assert_match(/pkce/i, params.fetch("error_description"))
  end

  def test_dynamic_registration_rejects_pkce_opt_out
    auth = build_auth
    cookie = sign_up_cookie(auth)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.register_o_auth_client(
        headers: {"cookie" => cookie},
        body: {
          redirect_uris: ["https://resource.example/callback"],
          token_endpoint_auth_method: "client_secret_post",
          grant_types: ["authorization_code"],
          response_types: ["code"],
          client_name: "Confidential Browser Client",
          scope: "read",
          require_pkce: false
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/pkce/i, error.message)
  end

  def test_authorize_rejects_scopes_outside_client_registration
    auth = build_auth(scopes: ["read", "write"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Scoped Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "write",
        state: "state-scope",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "invalid_scope", params.fetch("error")
  end

  def test_authorize_rejects_plain_pkce_challenge_method
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Public Browser Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "state-pkce",
        code_challenge: "plain-verifier",
        code_challenge_method: "plain"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "invalid_request", params.fetch("error")
    assert_match(/S256/i, params.fetch("error_description"))
  end

  def test_openid_metadata_is_not_available_without_openid_scope
    auth = build_auth(scopes: ["read"])

    error = assert_raises(BetterAuth::APIError) do
      auth.api.get_open_id_config
    end

    assert_equal 404, error.status_code
  end

  def test_metadata_supports_advertised_overrides_and_cache_headers
    auth = build_auth(
      scopes: ["openid", "profile", "email"],
      advertised_metadata: {
        scopes_supported: ["openid", "profile"],
        claims_supported: ["sub", "name"]
      }
    )

    status, headers, body = auth.api.get_open_id_config(as_response: true)
    metadata = JSON.parse(body.join, symbolize_names: true)

    assert_equal 200, status
    assert_equal "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400", headers.fetch("cache-control")
    refute metadata.key?(:jwks_uri)
    assert_equal ["openid", "profile"], metadata[:scopes_supported]
    assert_equal ["sub", "name"], metadata[:claims_supported]
  end

  def test_metadata_advertises_configured_jwks_uri_only_when_available
    auth = build_auth(
      scopes: ["openid"],
      advertised_metadata: {
        jwks_uri: "https://issuer.example/.well-known/jwks.json"
      }
    )

    metadata = auth.api.get_open_id_config
    server_metadata = auth.api.get_o_auth_server_config

    assert_equal "https://issuer.example/.well-known/jwks.json", metadata[:jwks_uri]
    assert_equal "https://issuer.example/.well-known/jwks.json", server_metadata[:jwks_uri]
  end

  def test_userinfo_requires_openid_scope
    auth = build_auth(scopes: ["openid", "profile", "email"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Machine Client",
        scope: "profile email"
      }
    )

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "profile email"
      }
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_user_info(headers: {"authorization" => "Bearer #{tokens[:access_token]}"})
    end

    assert_equal 403, error.status_code
  end

  def test_userinfo_returns_standard_openid_profile_and_email_claims
    auth = build_auth(scopes: ["openid", "profile", "email"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Browser Client",
        scope: "openid profile email"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "openid profile email",
        state: "state-userinfo",
        prompt: "consent",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    consent_code = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query).fetch("consent_code")
    consent = auth.api.o_auth2_consent(
      headers: {"cookie" => cookie},
      body: {accept: true, consent_code: consent_code}
    )
    code = Rack::Utils.parse_query(URI.parse(consent.fetch(:redirectURI)).query).fetch("code")
    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "https://resource.example/callback",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        code_verifier: pkce_verifier
      }
    )

    userinfo = auth.api.o_auth2_user_info(headers: {"authorization" => "Bearer #{tokens[:access_token]}"})

    assert userinfo[:sub]
    assert_equal "OAuth Owner", userinfo[:name]
    assert_equal "oauth-provider@example.com", userinfo[:email]
    assert_equal false, userinfo[:email_verified]
  end

  def test_token_prefixes_are_returned_and_respected_by_introspection
    auth = build_auth(
      scopes: ["openid", "offline_access"],
      prefix: {
        opaque_access_token: "hello_at_",
        refresh_token: "hello_rt_",
        client_secret: "hello_cs_"
      }
    )
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Prefixed Client",
        scope: "openid offline_access"
      }
    )
    assert client[:client_secret].start_with?("hello_cs_")

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid offline_access")
    assert tokens[:access_token].start_with?("hello_at_")
    assert tokens[:refresh_token].start_with?("hello_rt_")

    access = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal true, access[:active]
    assert_equal "openid offline_access", access[:scope]

    refresh = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:refresh_token],
        token_type_hint: "refresh_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal true, refresh[:active]
    assert_equal "openid offline_access", refresh[:scope]

    wrong_hint = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:access_token],
        token_type_hint: "refresh_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal false, wrong_hint[:active]
  end

  def test_refresh_token_rotation_prevents_replay_and_reduces_scopes
    auth = build_auth(scopes: ["openid", "profile", "offline_access"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Refresh Client",
        scope: "openid profile offline_access"
      }
    )
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile offline_access")

    refreshed = auth.api.o_auth2_token(
      body: {
        grant_type: "refresh_token",
        refresh_token: tokens[:refresh_token],
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "openid"
      }
    )
    assert refreshed[:refresh_token]
    assert_equal "openid", refreshed[:scope]

    replay_error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "refresh_token",
          refresh_token: tokens[:refresh_token],
          client_id: client[:client_id],
          client_secret: client[:client_secret]
        }
      )
    end
    assert_equal 400, replay_error.status_code
    assert_match(/invalid_grant/i, replay_error.message)

    cascade_error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "refresh_token",
          refresh_token: refreshed[:refresh_token],
          client_id: client[:client_id],
          client_secret: client[:client_secret]
        }
      )
    end
    assert_equal 400, cascade_error.status_code
  end

  def test_id_token_includes_nonce_and_preserves_auth_time_after_refresh
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "OIDC Refresh Client",
        scope: "openid offline_access"
      }
    )

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid offline_access", nonce: "nonce-123")
    id_token = JWT.decode(tokens[:id_token], client[:client_id], true, algorithm: "HS256").first

    assert_equal "nonce-123", id_token["nonce"]
    assert_kind_of Integer, id_token["auth_time"]

    refreshed = auth.api.o_auth2_token(
      body: {
        grant_type: "refresh_token",
        refresh_token: tokens[:refresh_token],
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "openid offline_access"
      }
    )
    refreshed_id_token = JWT.decode(refreshed[:id_token], client[:client_id], true, algorithm: "HS256").first
    assert_equal id_token["auth_time"], refreshed_id_token["auth_time"]
  end

  def test_token_endpoint_rejects_grants_not_registered_for_client
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Authorization Code Only Client",
        scope: "read"
      }
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "client_credentials",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          scope: "read"
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/unsupported_grant_type/i, error.message)
  end

  def test_token_endpoint_validates_requested_resource_audience
    auth = build_auth(scopes: ["read"], valid_audiences: ["https://api.example"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Resource Client",
        scope: "read"
      }
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "client_credentials",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          scope: "read",
          resource: "https://wrong.example"
        }
      )
    end
    assert_equal 400, error.status_code
    assert_match(/resource/i, error.message)

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read",
        resource: "https://api.example"
      }
    )
    assert_equal "https://api.example", tokens[:audience]
  end

  def test_resource_request_issues_jwt_access_token_with_pinned_claims
    auth = build_auth(
      scopes: ["read"],
      valid_audiences: ["https://api.example"],
      custom_access_token_claims: ->(_info) { {tenant: "acme", aud: "https://evil.example", scope: "evil"} }
    )
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "JWT Resource Client",
        scope: "read"
      }
    )

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read",
        resource: "https://api.example"
      }
    )
    refute tokens[:access_token].start_with?("ba_at_")

    payload = JWT.decode(tokens[:access_token], SECRET, true, algorithm: "HS256").first
    assert_equal "https://api.example", payload["aud"]
    assert_equal client[:client_id], payload["azp"]
    assert_equal "read", payload["scope"]
    assert_equal "acme", payload["tenant"]

    active = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal true, active[:active]
    assert_equal client[:client_id], active[:client_id]
    assert_equal "read", active[:scope]
    assert_equal "https://api.example", active[:aud]
  end

  def test_custom_token_response_and_userinfo_claims
    auth = build_auth(
      scopes: ["openid", "profile"],
      custom_token_response_fields: ->(info) { {tenant: "acme", grant: info[:grant_type]} },
      custom_user_info_claims: ->(info) { {roles: ["admin"], requested: info[:scopes]} }
    )
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Custom Claims Client",
        scope: "openid profile"
      }
    )

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile")
    assert_equal "acme", tokens[:tenant]
    assert_equal "authorization_code", tokens[:grant]

    userinfo = auth.api.o_auth2_user_info(headers: {"authorization" => "Bearer #{tokens[:access_token]}"})
    assert_equal ["admin"], userinfo[:roles]
    assert_equal ["openid", "profile"], userinfo[:requested]
  end

  def test_pairwise_subjects_are_client_specific
    auth = build_auth(scopes: ["openid"], pairwise_secret: "pairwise-secret-with-enough-entropy-123")
    cookie = sign_up_cookie(auth)
    client_a = auth.api.create_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://a.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Pairwise A",
        scope: "openid",
        subject_type: "pairwise"
      }
    )
    client_b = auth.api.create_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://b.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Pairwise B",
        scope: "openid",
        subject_type: "pairwise"
      }
    )

    tokens_a = issue_authorization_code_tokens(auth, cookie, client_a, scope: "openid", redirect_uri: "https://a.example/callback")
    tokens_b = issue_authorization_code_tokens(auth, cookie, client_b, scope: "openid", redirect_uri: "https://b.example/callback")
    sub_a = JWT.decode(tokens_a[:id_token], client_a[:client_id], true, algorithm: "HS256").first.fetch("sub")
    sub_b = JWT.decode(tokens_b[:id_token], client_b[:client_id], true, algorithm: "HS256").first.fetch("sub")

    refute_equal sub_a, sub_b
    refute_equal auth.context.adapter.find_one(model: "user", where: [{field: "email", value: "oauth-provider@example.com"}]).fetch("id"), sub_a

    userinfo = auth.api.o_auth2_user_info(headers: {"authorization" => "Bearer #{tokens_a[:access_token]}"})
    assert_equal sub_a, userinfo[:sub]
  end

  def test_end_session_validates_id_token_and_redirects_to_registered_logout_uri
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        post_logout_redirect_uris: ["https://resource.example/logout"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Logout Client",
        scope: "openid",
        enable_end_session: true
      }
    )
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")

    status, headers, = auth.api.o_auth2_end_session(
      query: {
        id_token_hint: tokens[:id_token],
        post_logout_redirect_uri: "https://resource.example/logout",
        state: "logout-state"
      },
      as_response: true
    )

    assert_equal 302, status
    redirect = URI.parse(headers.fetch("location"))
    assert_equal "https://resource.example/logout", "#{redirect.scheme}://#{redirect.host}#{redirect.path}"
    assert_equal "logout-state", Rack::Utils.parse_query(redirect.query).fetch("state")
  end

  def test_end_session_rejects_clients_without_logout_enabled
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        post_logout_redirect_uris: ["https://resource.example/logout"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Logout Client",
        scope: "openid"
      }
    )
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_end_session(
        query: {
          id_token_hint: tokens[:id_token],
          post_logout_redirect_uri: "https://resource.example/logout"
        }
      )
    end

    assert_equal 401, error.status_code
  end

  def test_client_management_enforces_ownership_updates_and_rotates_secret
    auth = build_auth(prefix: {client_secret: "rot_"})
    owner_cookie = sign_up_cookie(auth)
    other_cookie = sign_up_cookie(auth, email: "other-oauth-owner@example.com")
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => owner_cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Original Client",
        scope: "read"
      }
    )

    assert_raises(BetterAuth::APIError) do
      auth.api.get_o_auth_client(headers: {"cookie" => other_cookie}, params: {id: client[:client_id]})
    end

    updated = auth.api.update_o_auth_client(
      headers: {"cookie" => owner_cookie},
      body: {
        client_id: client[:client_id],
        update: {client_name: "Updated Client", scope: "read write"}
      }
    )
    assert_equal "Updated Client", updated[:client_name]
    assert_nil updated[:client_secret]
    assert_equal "read write", updated[:scope]

    rotated = auth.api.rotate_o_auth_client_secret(
      headers: {"cookie" => owner_cookie},
      body: {client_id: client[:client_id]}
    )
    assert rotated[:client_secret].start_with?("rot_")
    refute_equal client[:client_secret], rotated[:client_secret]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "client_credentials",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          scope: "read"
        }
      )
    end
    assert_equal 401, error.status_code
  end

  def test_user_create_client_does_not_require_dynamic_registration
    auth = build_auth(allow_dynamic_client_registration: false)
    cookie = sign_up_cookie(auth)

    client = auth.api.create_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "User Created Client",
        scope: "read",
        skip_consent: true,
        require_pkce: false
      }
    )

    assert_equal "User Created Client", client[:client_name]
    assert_equal true, client[:skip_consent]
    assert_equal false, client[:require_pkce]
    assert client[:user_id]
  end

  def test_client_privileges_can_block_management_actions
    auth = build_auth(client_privileges: ->(info) { info[:action] != "create" })
    cookie = sign_up_cookie(auth)

    create_error = assert_raises(BetterAuth::APIError) do
      auth.api.create_o_auth_client(
        headers: {"cookie" => cookie},
        body: {
          redirect_uris: ["https://resource.example/callback"],
          token_endpoint_auth_method: "client_secret_post",
          grant_types: ["client_credentials"],
          response_types: [],
          client_name: "Blocked Client",
          scope: "read"
        }
      )
    end
    assert_equal 401, create_error.status_code

    restricted_auth = build_auth(client_privileges: ->(info) { info[:action] != "rotate" })
    restricted_cookie = sign_up_cookie(restricted_auth)
    client = restricted_auth.api.create_o_auth_client(
      headers: {"cookie" => restricted_cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Rotate Blocked Client",
        scope: "read"
      }
    )

    rotate_error = assert_raises(BetterAuth::APIError) do
      restricted_auth.api.rotate_o_auth_client_secret(
        headers: {"cookie" => restricted_cookie},
        body: {client_id: client[:client_id]}
      )
    end
    assert_equal 401, rotate_error.status_code
  end

  def test_public_client_prelogin_returns_only_public_client_fields
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Public View Client",
        client_uri: "https://resource.example",
        logo_uri: "https://resource.example/icon.png",
        scope: "read"
      }
    )

    public_client = auth.api.get_o_auth_client_public_prelogin(query: {client_id: client[:client_id]})

    assert_equal client[:client_id], public_client[:client_id]
    assert_equal "Public View Client", public_client[:client_name]
    assert_equal "https://resource.example", public_client[:client_uri]
    assert_equal "https://resource.example/icon.png", public_client[:logo_uri]
    assert_nil public_client[:client_secret]
    refute public_client.key?(:redirect_uris)
  end

  def test_consent_management_lists_updates_and_deletes_user_consent
    auth = build_auth(scopes: ["openid", "profile"])
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Consent Client",
        scope: "openid profile"
      }
    )
    issue_authorization_code_tokens(auth, cookie, client, scope: "openid profile")

    listed = auth.api.list_o_auth_consents(headers: {"cookie" => cookie})
    assert_equal [client[:client_id]], listed.map { |consent| consent[:client_id] }

    consent = auth.api.get_o_auth_consent(headers: {"cookie" => cookie}, query: {client_id: client[:client_id]})
    assert_equal "openid profile", consent[:scope]

    updated = auth.api.update_o_auth_consent(
      headers: {"cookie" => cookie},
      body: {client_id: client[:client_id], scopes: ["openid"]}
    )
    assert_equal "openid", updated[:scope]

    deleted = auth.api.delete_o_auth_consent(headers: {"cookie" => cookie}, body: {client_id: client[:client_id]})
    assert_equal({deleted: true}, deleted)
    assert_equal [], auth.api.list_o_auth_consents(headers: {"cookie" => cookie})
  end

  def test_authorize_prompt_none_returns_consent_required_without_prior_consent
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Prompt None Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "state-456",
        prompt: "none",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "consent_required", params.fetch("error")
    assert_equal "state-456", params.fetch("state")
  end

  private

  def build_auth(options = {})
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.oauth_provider({scopes: ["read", "write"], allow_dynamic_client_registration: true}.merge(options))]
    )
  end

  def oauth_rate_limit_path(rule)
    %w[
      /oauth2/token
      /oauth2/authorize
      /oauth2/introspect
      /oauth2/revoke
      /oauth2/register
      /oauth2/userinfo
    ].find { |path| rule.fetch(:path_matcher).call(path) }
  end

  def pkce_verifier
    "a" * 64
  end

  def pkce_challenge
    Base64.urlsafe_encode64(OpenSSL::Digest.digest("SHA256", pkce_verifier), padding: false)
  end

  def issue_authorization_code_tokens(auth, cookie, client, scope:, redirect_uri: "https://resource.example/callback", nonce: nil)
    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: redirect_uri,
        scope: scope,
        state: "state-token",
        prompt: "consent",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256",
        nonce: nonce
      }.compact,
      as_response: true
    )
    assert_equal 302, status
    consent_code = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query).fetch("consent_code")
    consent = auth.api.o_auth2_consent(
      headers: {"cookie" => cookie},
      body: {accept: true, consent_code: consent_code}
    )
    code = Rack::Utils.parse_query(URI.parse(consent.fetch(:redirectURI)).query).fetch("code")
    auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirect_uri,
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        code_verifier: pkce_verifier
      }
    )
  end

  def sign_up_cookie(auth, email: "oauth-provider@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "OAuth Owner"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
