# frozen_string_literal: true

require_relative "../../test_helper"

class OAuthProviderIntrospectTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_introspect_reports_active_opaque_access_token
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid offline_access", skip_consent: true)
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid offline_access")

    response = auth.api.o_auth2_introspect(body: introspect_body(client, tokens[:access_token]))

    assert_equal true, response[:active]
    assert_equal client[:client_id], response[:client_id]
    assert_equal "openid offline_access", response[:scope]
    assert_equal "http://localhost:3000", response[:iss]
  end
end
