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
