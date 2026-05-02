# frozen_string_literal: true

require_relative "../../test_helper"

class OAuthProviderRevokeTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_revoke_access_token_makes_introspection_inactive
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")

    assert_equal({revoked: true}, auth.api.o_auth2_revoke(body: revoke_body(client, tokens[:access_token], hint: "access_token")))

    inactive = auth.api.o_auth2_introspect(body: introspect_body(client, tokens[:access_token], hint: "access_token"))
    assert_equal false, inactive[:active]
  end
end
