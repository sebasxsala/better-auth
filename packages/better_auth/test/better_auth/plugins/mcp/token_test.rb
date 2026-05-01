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
    auth = build_mcp_auth(valid_audiences: ["http://localhost:5000/mcp"], scopes: %w[openid profile email offline_access greeting])
    cookie = sign_up_cookie(auth)
    client = register_public_mcp_client(auth, scope: "openid offline_access greeting")
    code = authorize_mcp_code(auth, cookie, client, scope: "openid offline_access greeting", resource: "http://localhost:5000/mcp")

    tokens = exchange_mcp_code(auth, client, code, resource: "http://localhost:5000/mcp")
    payload = JWT.decode(tokens[:access_token], MCPTestHelpers::SECRET, true, algorithm: "HS256").first

    assert_equal "http://localhost:5000/mcp", payload["aud"]
    assert_equal "openid offline_access greeting", payload["scope"]
    assert_equal client[:client_id], payload["azp"]
  end

  def test_confidential_client_requires_secret_and_supports_basic_auth
    auth = build_mcp_auth
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
    code = authorize_mcp_code(auth, cookie, client, redirect_uri: "https://mcp.example/confidential", scope: "openid email")

    missing_secret = assert_raises(BetterAuth::APIError) do
      auth.api.mcp_o_auth_token(
        body: {
          grant_type: "authorization_code",
          code: code,
          redirect_uri: "https://mcp.example/confidential",
          client_id: client[:client_id],
          code_verifier: pkce_verifier
        }
      )
    end
    assert_equal 401, missing_secret.status_code

    code = authorize_mcp_code(auth, cookie, client, redirect_uri: "https://mcp.example/confidential", scope: "openid email")
    basic = Base64.strict_encode64("#{client[:client_id]}:#{client[:client_secret]}")
    tokens = auth.api.mcp_o_auth_token(
      headers: {"authorization" => "Basic #{basic}"},
      body: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "https://mcp.example/confidential",
        code_verifier: pkce_verifier
      }
    )

    assert tokens[:access_token]
    assert_nil tokens[:refresh_token]
  end
end
