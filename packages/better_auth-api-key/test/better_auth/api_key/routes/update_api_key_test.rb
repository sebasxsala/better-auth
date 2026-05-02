# frozen_string_literal: true

require_relative "../test_support"

class BetterAuthAPIKeyUpdateRouteTest < Minitest::Test
  include APIKeyTestSupport

  def test_update_route_preserves_usage_fields
    auth = build_api_key_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "update-route-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {remaining: nil})

    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], name: "updated"})

    assert_equal "updated", updated[:name]
    assert_nil updated[:lastRequest]
    assert_nil updated[:remaining]
  end

  def test_update_route_rejects_noop_and_authenticated_client_server_only_fields
    auth = build_api_key_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "update-route-server-only-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    no_values = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id]})
    end
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("NO_VALUES_TO_UPDATE"), no_values.message

    %i[permissions refillAmount refillInterval rateLimitMax rateLimitTimeWindow rateLimitEnabled remaining].each do |field|
      error = assert_raises(BetterAuth::APIError) do
        body = {keyId: created[:id]}
        body[field] = 10
        auth.api.update_api_key(headers: {"cookie" => cookie}, body: body)
      end

      assert_equal "BAD_REQUEST", error.status
      assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("SERVER_ONLY_PROPERTY"), error.message
    end
  end

  def test_update_route_supports_server_side_mutations_and_preserves_config_id
    auth = build_api_key_auth(default_key_length: 12, enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "update-route-server-mutation-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 5})

    updated = auth.api.update_api_key(body: {
      userId: user_id,
      keyId: created[:id],
      name: "updated",
      enabled: false,
      remaining: 1,
      expiresIn: nil,
      metadata: {tier: "pro"},
      permissions: {repo: ["read"]}
    })

    assert_equal "updated", updated[:name]
    assert_equal false, updated[:enabled]
    assert_equal 1, updated[:remaining]
    assert_nil updated[:expiresAt]
    assert_equal "default", updated[:configId]
    assert_equal({"tier" => "pro"}, updated[:metadata])
    assert_equal({"repo" => ["read"]}, updated[:permissions])
  end

  def test_update_route_rejects_refill_pairs_and_expiration_bounds
    auth = build_api_key_auth(default_key_length: 12, key_expiration: {min_expires_in: 1, max_expires_in: 2})
    cookie = sign_up_cookie(auth, email: "update-route-validation-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    refill_error = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], refillAmount: 10})
    end
    small_expiration = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], expiresIn: 1})
    end
    large_expiration = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], expiresIn: 60 * 60 * 24 * 365})
    end

    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("REFILL_AMOUNT_AND_INTERVAL_REQUIRED"), refill_error.message
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("EXPIRES_IN_IS_TOO_SMALL"), small_expiration.message
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("EXPIRES_IN_IS_TOO_LARGE"), large_expiration.message
  end
end
