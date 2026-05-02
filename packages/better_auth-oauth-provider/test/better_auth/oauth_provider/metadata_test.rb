# frozen_string_literal: true

require_relative "../../test_helper"

class OAuthProviderMetadataTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_authorization_server_metadata_matches_upstream_endpoints_and_cache_headers
    auth = build_auth(scopes: ["openid", "profile", "email"])

    response = auth.api.get_o_auth_server_config(as_response: true)
    body = JSON.parse(response.body.join, symbolize_names: true)

    assert_equal 200, response.status
    assert_equal "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400", response.headers["cache-control"]
    assert_equal "http://localhost:3000", body[:issuer]
    assert_equal "http://localhost:3000/api/auth/oauth2/authorize", body[:authorization_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/token", body[:token_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/register", body[:registration_endpoint]
    assert_equal ["code"], body[:response_types_supported]
  end
end
