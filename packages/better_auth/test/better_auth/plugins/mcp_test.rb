# frozen_string_literal: true

require "base64"
require "rack/mock"
require_relative "../../test_helper"

class BetterAuthPluginsMCPTest < Minitest::Test
  SECRET = "phase-eleven-secret-with-enough-entropy-123"

  def test_mcp_metadata_public_client_pkce_token_refresh_and_userinfo
    auth = build_auth
    cookie = sign_up_cookie(auth)

    server = auth.api.get_mcp_o_auth_config
    assert_equal "http://localhost:3000", server[:issuer]
    assert_equal "http://localhost:3000/api/auth/mcp/authorize", server[:authorization_endpoint]
    assert_equal "http://localhost:3000/api/auth/mcp/token", server[:token_endpoint]

    resource = auth.api.get_mcp_protected_resource
    assert_equal "http://localhost:3000", resource[:resource]
    assert_equal ["http://localhost:3000"], resource[:authorization_servers]
    assert_equal ["header"], resource[:bearer_methods_supported]

    client = auth.api.mcp_register(
      body: {
        redirect_uris: ["https://mcp.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "MCP Client"
      }
    )
    assert_nil client[:client_secret]

    verifier = "mcp-code-verifier-123456789012345678901234567890"
    challenge = Base64.urlsafe_encode64(OpenSSL::Digest.digest("SHA256", verifier), padding: false)
    status, headers, _body = auth.api.mcp_o_auth_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://mcp.example/callback",
        scope: "openid email offline_access",
        code_challenge: challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, status
    code = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query).fetch("code")

    tokens = auth.api.mcp_o_auth_token(
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "https://mcp.example/callback",
        client_id: client[:client_id],
        code_verifier: verifier
      }
    )
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

    userinfo = auth.api.mcp_o_auth_user_info(headers: {"authorization" => "Bearer #{refreshed[:access_token]}"})
    assert_equal "mcp@example.com", userinfo[:email]

    session = auth.api.get_mcp_session(headers: {"authorization" => "Bearer #{refreshed[:access_token]}"})
    assert_equal client[:client_id], session["clientId"]

    app = BetterAuth::Plugins::MCP.with_mcp_auth(
      ->(env) { [200, {}, [env.fetch("better_auth.mcp_session").fetch("userId")]] },
      auth: auth,
      resource_metadata_url: "http://localhost:3000/.well-known/oauth-protected-resource"
    )
    status, _headers, body = app.call({"HTTP_AUTHORIZATION" => "Bearer #{refreshed[:access_token]}"})
    assert_equal 200, status
    assert_equal [auth.context.internal_adapter.find_user_by_email("mcp@example.com")[:user]["id"]], body

    invalid_status, invalid_headers, _invalid_body = app.call({"HTTP_AUTHORIZATION" => "Bearer invalid-token"})
    assert_equal 401, invalid_status
    assert_includes invalid_headers.fetch("www-authenticate"), "Bearer"
  end

  def test_with_mcp_auth_returns_www_authenticate_for_missing_bearer_token
    app = BetterAuth::Plugins::MCP.with_mcp_auth(->(_env) { [200, {}, ["ok"]] }, resource_metadata_url: "http://localhost:3000/.well-known/oauth-protected-resource")

    status, headers, body = app.call({})

    assert_equal 401, status
    assert_equal ["unauthorized"], body
    assert_includes headers.fetch("www-authenticate"), "Bearer"
    assert_includes headers.fetch("www-authenticate"), "resource_metadata=\"http://localhost:3000/.well-known/oauth-protected-resource\""
    assert_equal "WWW-Authenticate", headers.fetch("access-control-expose-headers")
  end

  def test_mcp_jwks_publishes_jwt_plugin_signing_keys
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.mcp(login_page: "/login"),
        BetterAuth::Plugins.jwt
      ]
    )

    token = auth.api.sign_jwt(body: {payload: {sub: "mcp-user"}})[:token]
    _payload, header = JWT.decode(token, nil, false)
    jwks = auth.api.mcp_jwks

    assert_equal [header.fetch("kid")], jwks.fetch(:keys).map { |key| key.fetch(:kid) }
    assert_equal "OKP", jwks.fetch(:keys).first.fetch(:kty)
    assert_equal "EdDSA", jwks.fetch(:keys).first.fetch(:alg)
  end

  def test_mcp_authorize_restores_login_prompt_cookie_after_email_sign_in
    auth = build_auth
    auth.api.sign_up_email(body: {email: "prompt@example.com", password: "password123", name: "Prompt User"})
    auth.api.sign_out
    client = auth.api.mcp_register(
      body: {
        redirect_uris: ["https://mcp.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Prompt Client"
      }
    )

    request = Rack::MockRequest.new(auth)
    authorize = request.get(
      "/api/auth/mcp/authorize",
      params: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://mcp.example/callback",
        scope: "openid profile email",
        state: "restore-state",
        prompt: "login",
        code_challenge: "plain-challenge",
        code_challenge_method: "plain"
      }
    )

    assert_equal 302, authorize.status
    assert_includes authorize["location"], "/login"
    oidc_cookie = cookie_header(authorize["set-cookie"])
    assert_includes oidc_cookie, "oidc_login_prompt="

    sign_in = request.post(
      "/api/auth/sign-in/email",
      "CONTENT_TYPE" => "application/json",
      "HTTP_COOKIE" => oidc_cookie,
      "HTTP_ORIGIN" => "http://localhost:3000",
      :input => JSON.generate({email: "prompt@example.com", password: "password123"})
    )

    assert_equal 302, sign_in.status
    redirect = URI.parse(sign_in["location"])
    params = Rack::Utils.parse_query(redirect.query)
    assert_equal "https", redirect.scheme
    assert_equal "mcp.example", redirect.host
    assert_equal "/callback", redirect.path
    assert_equal "restore-state", params.fetch("state")
    assert_match(/\A[A-Za-z0-9_-]{32}\z/, params.fetch("code"))
    assert_includes sign_in["set-cookie"], "oidc_login_prompt=;"
  end

  def test_mcp_confidential_client_requires_secret_and_supports_basic_auth
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.mcp_register(
      body: {
        redirect_uris: ["https://mcp.example/confidential"],
        token_endpoint_auth_method: "client_secret_basic",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Confidential MCP Client"
      }
    )
    status, headers, _body = auth.api.mcp_o_auth_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://mcp.example/confidential",
        scope: "openid email"
      },
      as_response: true
    )
    assert_equal 302, status
    code = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query).fetch("code")

    missing_secret = assert_raises(BetterAuth::APIError) do
      auth.api.mcp_o_auth_token(
        body: {
          grant_type: "authorization_code",
          code: code,
          redirect_uri: "https://mcp.example/confidential",
          client_id: client[:client_id]
        }
      )
    end
    assert_equal 401, missing_secret.status_code

    _status, headers, _body = auth.api.mcp_o_auth_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://mcp.example/confidential",
        scope: "openid email"
      },
      as_response: true
    )
    code = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query).fetch("code")
    basic = Base64.strict_encode64("#{client[:client_id]}:#{client[:client_secret]}")
    tokens = auth.api.mcp_o_auth_token(
      headers: {"authorization" => "Basic #{basic}"},
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "https://mcp.example/confidential"
      }
    )

    assert tokens[:access_token]
    assert_nil tokens[:refresh_token]
  end

  def test_mcp_rejects_invalid_authorize_requests
    auth = build_auth(require_pkce: true, oidc_config: {scopes: %w[openid email]})
    cookie = sign_up_cookie(auth)
    client = auth.api.mcp_register(
      body: {
        redirect_uris: ["https://mcp.example/reject"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Reject Client"
      }
    )

    unsupported = auth.api.mcp_o_auth_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "token",
        client_id: client[:client_id],
        redirect_uri: "https://mcp.example/reject",
        scope: "openid"
      },
      as_response: true
    )
    assert_equal 302, unsupported.first
    assert_includes unsupported[1].fetch("location"), "error=unsupported_response_type"

    invalid_scope = auth.api.mcp_o_auth_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://mcp.example/reject",
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
        redirect_uri: "https://mcp.example/reject",
        scope: "openid"
      },
      as_response: true
    )
    assert_equal 302, missing_pkce.first
    assert_includes missing_pkce[1].fetch("location"), "error=invalid_request"
    assert_includes missing_pkce[1].fetch("location"), "pkce+is+required"
  end

  private

  def build_auth(options = {})
    BetterAuth.auth(
      {
        base_url: "http://localhost:3000",
        secret: SECRET,
        database: :memory,
        email_and_password: {enabled: true},
        plugins: [BetterAuth::Plugins.mcp({login_page: "/login"}.merge(options))]
      }
    )
  end

  def sign_up_cookie(auth)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "mcp@example.com", password: "password123", name: "MCP User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end
end
