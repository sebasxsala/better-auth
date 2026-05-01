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
    auth = build_mcp_auth(valid_audiences: ["http://localhost:5000/mcp"], scopes: %w[openid profile email offline_access greeting])
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
