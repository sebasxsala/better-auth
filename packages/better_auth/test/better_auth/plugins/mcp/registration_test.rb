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
