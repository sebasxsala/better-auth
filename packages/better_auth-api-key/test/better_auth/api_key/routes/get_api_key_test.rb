# frozen_string_literal: true

require_relative "../test_support"

class BetterAuthAPIKeyGetRouteTest < Minitest::Test
  include APIKeyTestSupport

  def test_get_route_does_not_reveal_secret_key
    auth = build_api_key_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "get-route-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})

    assert_equal created[:id], fetched[:id]
    refute fetched.key?(:key)
  end

  def test_get_route_decodes_metadata_permissions_and_unknown_id_is_not_found
    auth = build_api_key_auth(default_key_length: 12, enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "get-route-shape-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(
      body: {userId: user_id, metadata: {tier: "pro"}, permissions: {repo: ["read"]}}
    )

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: "missing"})
    end
    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})

    assert_equal "NOT_FOUND", missing.status
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("KEY_NOT_FOUND"), missing.message
    assert_equal({"tier" => "pro"}, fetched[:metadata])
    assert_equal({"repo" => ["read"]}, fetched[:permissions])
  end

  def test_get_route_rejects_wrong_user_as_not_found
    auth = build_api_key_auth(default_key_length: 12)
    owner_cookie = sign_up_cookie(auth, email: "get-route-owner-key@example.com")
    other_cookie = sign_up_cookie(auth, email: "get-route-other-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.get_api_key(headers: {"cookie" => other_cookie}, query: {id: created[:id]})
    end

    assert_equal "NOT_FOUND", error.status
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("KEY_NOT_FOUND"), error.message
  end
end
