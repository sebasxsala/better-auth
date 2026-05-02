# frozen_string_literal: true

require_relative "test_helper"

class BetterAuthPluginsMCPLegacyAliasesTest < Minitest::Test
  include MCPTestHelpers

  def test_legacy_mcp_routes_delegate_to_canonical_storage
    auth = build_mcp_auth
    cookie = sign_up_cookie(auth)
    request = Rack::MockRequest.new(auth)

    register = request.post(
      "/api/auth/mcp/register",
      "CONTENT_TYPE" => "application/json",
      :input => JSON.generate({
        redirect_uris: ["https://mcp.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Legacy Alias Client",
        scope: "openid offline_access"
      })
    )
    assert_equal 201, register.status
    client = JSON.parse(register.body, symbolize_names: true)

    assert auth.context.adapter.find_one(model: "oauthClient", where: [{field: "clientId", value: client[:client_id]}])
    authorize = request.get(
      "/api/auth/mcp/authorize",
      "HTTP_COOKIE" => cookie,
      :params => {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://mcp.example/callback",
        scope: "openid offline_access",
        code_challenge: pkce_challenge,
        code_challenge_method: "S256"
      }
    )
    assert_equal 302, authorize.status
    code = Rack::Utils.parse_query(URI.parse(authorize["location"]).query).fetch("code")

    token = request.post(
      "/api/auth/mcp/token",
      "CONTENT_TYPE" => "application/json",
      :input => JSON.generate({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "https://mcp.example/callback",
        client_id: client[:client_id],
        code_verifier: pkce_verifier
      })
    )
    assert_equal 200, token.status
    tokens = JSON.parse(token.body, symbolize_names: true)
    assert tokens[:access_token]
  end
end
