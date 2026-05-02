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

  def test_mcp_jwks_publishes_jwt_plugin_signing_keys
    auth = build_mcp_auth(extra_plugins: [BetterAuth::Plugins.jwt])

    token = auth.api.sign_jwt(body: {payload: {sub: "mcp-user"}})[:token]
    _payload, header = JWT.decode(token, nil, false)
    jwks = auth.api.mcp_jwks

    assert_equal [header.fetch("kid")], jwks.fetch(:keys).map { |key| key.fetch(:kid) }
    assert_equal "OKP", jwks.fetch(:keys).first.fetch(:kty)
    assert_equal "EdDSA", jwks.fetch(:keys).first.fetch(:alg)
  end
end
