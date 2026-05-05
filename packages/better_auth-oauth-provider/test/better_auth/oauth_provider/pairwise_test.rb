# frozen_string_literal: true

require "jwt"
require_relative "../../test_helper"

class OAuthProviderPairwiseTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_pairwise_subject_is_stable_for_same_sector
    auth = build_auth(scopes: ["openid"], pairwise_secret: "pairwise-secret-with-enough-entropy-123")
    cookie = sign_up_cookie(auth)
    client_a = auth.api.admin_create_o_auth_client(body: pairwise_client_body("https://sector.example.com/a/callback"))
    client_b = auth.api.admin_create_o_auth_client(body: pairwise_client_body("https://sector.example.com/b/callback"))

    tokens_a = issue_authorization_code_tokens(auth, cookie, client_a, scope: "openid", redirect_uri: "https://sector.example.com/a/callback")
    tokens_b = issue_authorization_code_tokens(auth, cookie, client_b, scope: "openid", redirect_uri: "https://sector.example.com/b/callback")
    sub_a = decode_id_token(tokens_a[:id_token], client_a).fetch("sub")
    sub_b = decode_id_token(tokens_b[:id_token], client_b).fetch("sub")

    assert_equal sub_a, sub_b
  end
end
