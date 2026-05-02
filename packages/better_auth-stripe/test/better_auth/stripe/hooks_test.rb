# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthStripeHooksTest < Minitest::Test
  def test_hooks_expose_upstream_handler_names
    assert_respond_to BetterAuth::Stripe::Hooks, :handle_event
    assert_respond_to BetterAuth::Stripe::Hooks, :on_checkout_completed
    assert_respond_to BetterAuth::Stripe::Hooks, :on_subscription_created
    assert_respond_to BetterAuth::Stripe::Hooks, :on_subscription_updated
    assert_respond_to BetterAuth::Stripe::Hooks, :on_subscription_deleted
  end
end
