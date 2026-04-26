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
  end

  def test_with_mcp_auth_returns_www_authenticate_for_missing_bearer_token
    app = BetterAuth::Plugins::MCP.with_mcp_auth(->(_env) { [200, {}, ["ok"]] }, resource_metadata_url: "http://localhost:3000/.well-known/oauth-protected-resource")

    status, headers, body = app.call({})

    assert_equal 401, status
    assert_equal ["unauthorized"], body
    assert_includes headers.fetch("www-authenticate"), "Bearer"
    assert_includes headers.fetch("www-authenticate"), "resource_metadata=\"http://localhost:3000/.well-known/oauth-protected-resource\""
  end

  private

  def build_auth
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.mcp(login_page: "/login")]
    )
  end

  def sign_up_cookie(auth)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "mcp@example.com", password: "password123", name: "MCP User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
