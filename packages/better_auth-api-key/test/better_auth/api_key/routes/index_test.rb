# frozen_string_literal: true

require_relative "../test_support"

class BetterAuthAPIKeyRoutesIndexTest < Minitest::Test
  include APIKeyTestSupport

  def setup
    BetterAuth::APIKey::Routes.instance_variable_set(:@last_expired_check, nil)
  end

  def test_config_id_matching_treats_nil_empty_and_default_as_default
    assert BetterAuth::APIKey::Routes.default_config_id?(nil)
    assert BetterAuth::APIKey::Routes.default_config_id?("")
    assert BetterAuth::APIKey::Routes.default_config_id?("default")
    assert BetterAuth::APIKey::Routes.config_id_matches?(nil, "default")
    assert BetterAuth::APIKey::Routes.config_id_matches?("", nil)
    refute BetterAuth::APIKey::Routes.config_id_matches?("service", "default")
  end

  def test_resolve_config_falls_back_to_default_when_requested_id_is_unknown
    logger = Struct.new(:messages) do
      def error(message)
        messages << message
      end
    end.new([])
    context = Struct.new(:logger).new(logger)
    config = BetterAuth::APIKey::Configuration.normalize([
      {config_id: "default", default_prefix: "def_", default_key_length: 12},
      {config_id: "service", default_prefix: "svc_", default_key_length: 12}
    ])

    selected = BetterAuth::APIKey::Routes.resolve_config(context, config, "missing")

    assert_equal "default", selected.fetch(:config_id)
    assert_equal "def_", selected.fetch(:default_prefix)
    assert_empty logger.messages
  end

  def test_delete_expired_throttles_regular_cleanup_and_bypass_deletes_immediately
    auth = build_api_key_auth(default_key_length: 12)
    config = BetterAuth::APIKey::Configuration.normalize({})
    first = create_expired_record(auth, "first-expired-key")

    BetterAuth::APIKey::Routes.delete_expired(auth.context, config)
    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: first.fetch("id")}])

    second = create_expired_record(auth, "second-expired-key")
    BetterAuth::APIKey::Routes.delete_expired(auth.context, config)
    assert auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: second.fetch("id")}])

    BetterAuth::APIKey::Routes.delete_expired(auth.context, config, bypass_last_check: true)
    assert_nil auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: second.fetch("id")}])
  end

  private

  def create_expired_record(auth, key)
    now = Time.now
    auth.context.adapter.create(
      model: "apikey",
      data: {
        configId: "default",
        createdAt: now,
        updatedAt: now,
        name: nil,
        prefix: nil,
        start: key[0, 6],
        key: key,
        enabled: true,
        expiresAt: now - 60,
        referenceId: "reference-id",
        lastRefillAt: nil,
        lastRequest: nil,
        metadata: nil,
        rateLimitMax: 10,
        rateLimitTimeWindow: 86_400_000,
        remaining: nil,
        refillAmount: nil,
        refillInterval: nil,
        rateLimitEnabled: true,
        requestCount: 0,
        permissions: nil
      }
    )
  end
end
