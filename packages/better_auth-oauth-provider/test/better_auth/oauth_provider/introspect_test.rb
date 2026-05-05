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

  def test_introspect_strips_bearer_prefix
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)
    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")

    response = auth.api.o_auth2_introspect(body: introspect_body(client, "Bearer #{tokens[:access_token]}"))

    assert_equal true, response[:active]
    assert_equal client[:client_id], response[:client_id]
  end

  def test_introspect_does_not_expose_tokens_to_other_clients
    auth = build_auth(scopes: ["openid", "offline_access"])
    cookie = sign_up_cookie(auth)
    owner = create_client(auth, cookie, scope: "openid offline_access", skip_consent: true)
    other = create_client(auth, cookie, scope: "openid offline_access", skip_consent: true)
    tokens = issue_authorization_code_tokens(auth, cookie, owner, scope: "openid offline_access")

    access = auth.api.o_auth2_introspect(body: introspect_body(other, tokens[:access_token], hint: "access_token"))
    refresh = auth.api.o_auth2_introspect(body: introspect_body(other, tokens[:refresh_token], hint: "refresh_token"))

    assert_equal false, access[:active]
    assert_equal false, refresh[:active]
  end
end
