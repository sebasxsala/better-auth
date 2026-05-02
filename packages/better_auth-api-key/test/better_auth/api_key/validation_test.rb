# frozen_string_literal: true

require_relative "test_support"

class BetterAuthAPIKeyValidationTest < Minitest::Test
  def test_validate_create_update_rejects_client_server_only_fields
    config = BetterAuth::APIKey::Configuration.normalize({})

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::APIKey::Validation.validate_create_update!(
        {permissions: {repo: ["read"]}},
        config,
        create: true,
        client: true
      )
    end

    assert_equal "BAD_REQUEST", error.status
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("SERVER_ONLY_PROPERTY"), error.message
  end

  def test_validate_create_update_allows_server_remaining_zero_on_create
    config = BetterAuth::APIKey::Configuration.normalize({})

    BetterAuth::APIKey::Validation.validate_create_update!({remaining: 0}, config, create: true, client: false)
  end

  def test_validate_create_update_rejects_mismatched_refill_fields
    config = BetterAuth::APIKey::Configuration.normalize({})

    interval_error = assert_raises(BetterAuth::APIError) do
      BetterAuth::APIKey::Validation.validate_create_update!({refill_interval: 1000}, config, create: true, client: false)
    end
    amount_error = assert_raises(BetterAuth::APIError) do
      BetterAuth::APIKey::Validation.validate_create_update!({refill_amount: 10}, config, create: true, client: false)
    end

    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("REFILL_INTERVAL_AND_AMOUNT_REQUIRED"), interval_error.message
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("REFILL_AMOUNT_AND_INTERVAL_REQUIRED"), amount_error.message
  end

  def test_update_payload_preserves_false_zero_nil_and_encodes_objects
    config = BetterAuth::APIKey::Configuration.normalize(enable_metadata: true)

    update = BetterAuth::APIKey::Validation.update_payload({
      enabled: false,
      remaining: 0,
      expires_in: nil,
      metadata: {tier: "pro"},
      permissions: {repo: ["read"]}
    }, config)

    assert_equal false, update.fetch(:enabled)
    assert_equal 0, update.fetch(:remaining)
    assert_nil update.fetch(:expiresAt)
    assert_equal({"tier" => "pro"}, JSON.parse(update.fetch(:metadata)))
    assert_equal({"repo" => ["read"]}, JSON.parse(update.fetch(:permissions)))
  end

  def test_usage_update_refills_remaining_after_interval_then_decrements
    config = BetterAuth::APIKey::Configuration.normalize(rate_limit: {enabled: false})
    record = {
      "remaining" => 0,
      "refillAmount" => 3,
      "refillInterval" => 1,
      "lastRefillAt" => Time.now - 60,
      "createdAt" => Time.now - 120
    }

    update = BetterAuth::APIKey::Validation.usage_update(record, config)

    assert_equal 2, update.fetch(:remaining)
    assert update.fetch(:lastRefillAt)
    refute update.key?(:requestCount)
  end

  def test_check_permissions_matches_upstream_key_not_found_failure
    record = {"permissions" => JSON.generate({"repo" => ["read"]})}

    BetterAuth::APIKey::Validation.check_permissions!(record, {repo: ["read"]})
    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::APIKey::Validation.check_permissions!(record, {repo: ["write"]})
    end

    assert_equal "UNAUTHORIZED", error.status
    assert_equal "KEY_NOT_FOUND", error.code
    assert_equal BetterAuth::APIKey::ERROR_CODES.fetch("KEY_NOT_FOUND"), error.message
  end
end
