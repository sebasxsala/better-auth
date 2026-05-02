# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthStripePluginFactoryTest < Minitest::Test
  def test_build_returns_stripe_plugin_with_schema_endpoints_and_error_codes
    plugin = BetterAuth::Stripe::PluginFactory.build(subscription: {enabled: true, plans: []})

    assert_equal "stripe", plugin.id
    assert_equal BetterAuth::Stripe::ERROR_CODES, plugin.error_codes
    assert plugin.schema.key?(:subscription)
    assert plugin.endpoints.key?(:upgrade_subscription)
  end

  def test_public_facade_delegates_to_plugin_factory
    plugin = BetterAuth::Plugins.stripe(subscription: {enabled: true, plans: []})

    assert_equal "stripe", plugin.id
    assert plugin.endpoints.key?(:stripe_webhook)
  end

  def test_plugin_version_is_exposed
    plugin = BetterAuth::Stripe::PluginFactory.build

    assert_equal BetterAuth::Stripe::VERSION, plugin.version
  end
end
