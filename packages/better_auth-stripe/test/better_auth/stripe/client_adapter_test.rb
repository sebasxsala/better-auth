# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthStripeClientAdapterTest < Minitest::Test
  def test_webhooks_adapter_supports_sync_and_async_construct_event
    adapter = BetterAuth::Stripe::WebhooksAdapter.new

    assert_respond_to adapter, :construct_event
    assert_respond_to adapter, :construct_event_async
  end

  def test_error_codes_are_exposed_through_compatibility_constant
    assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND"),
      BetterAuth::Plugins::STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")
  end
end
