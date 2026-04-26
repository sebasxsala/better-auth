# frozen_string_literal: true

require "rack/mock"
require_relative "../../test_helper"

class BetterAuthPluginsOAuthProviderTest < Minitest::Test
  SECRET = "phase-eleven-secret-with-enough-entropy-123"

  def test_validate_issuer_url_matches_rfc_9207_upstream_behavior
    assert_equal "https://issuer.example.com", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("https://issuer.example.com/")
    assert_equal "https://issuer.example.com/auth", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://issuer.example.com/auth?x=1#frag")
    assert_equal "http://localhost:3000", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://localhost:3000/")
    assert_equal "http://127.0.0.1:3000", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://127.0.0.1:3000/")
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

  private

  def build_auth
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.oauth_provider(scopes: ["read", "write"])]
    )
  end

  def sign_up_cookie(auth)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "oauth-provider@example.com", password: "password123", name: "OAuth Owner"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
