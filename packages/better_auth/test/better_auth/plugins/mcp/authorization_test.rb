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

  def test_consent_prompt_issues_code_with_granted_scopes
    auth = build_mcp_auth
    cookie = sign_up_cookie(auth)
    client = register_public_mcp_client(auth)

    consent = auth.api.mcp_o_auth_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://mcp.example/callback",
        scope: "openid email offline_access",
        state: "consent-state",
        prompt: "consent",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      },
      as_response: true
    )
    assert_equal 302, consent.first
    consent_params = Rack::Utils.parse_query(URI.parse(consent[1].fetch("location")).query)

    accepted = auth.api.o_auth_consent(
      headers: {"cookie" => cookie},
      body: {
        consent_code: consent_params.fetch("consent_code"),
        accept: true,
        scope: "openid"
      }
    )
    code = Rack::Utils.parse_query(URI.parse(accepted.fetch(:redirectURI)).query).fetch("code")
    tokens = exchange_mcp_code(auth, client, code)

    assert_equal "openid", tokens[:scope]
    refute tokens[:refresh_token]
  end

  def test_authorize_restores_login_prompt_cookie_after_email_sign_in
    auth = build_mcp_auth
    auth.api.sign_up_email(body: {email: "prompt@example.com", password: "password123", name: "Prompt User"})
    auth.api.sign_out
    client = register_public_mcp_client(auth, scope: "openid profile email")

    request = Rack::MockRequest.new(auth)
    authorize = request.get(
      "/api/auth/oauth2/authorize",
      params: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://mcp.example/callback",
        scope: "openid profile email",
        state: "restore-state",
        prompt: "login",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
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
    assert_match(/\A[A-Za-z0-9_-]{32,}\z/, params.fetch("code"))
    assert_includes sign_in["set-cookie"], "oidc_login_prompt=;"
  end
end
