# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthStripeRoutesSubscriptionSuccessTest < Minitest::Test
  def test_success_endpoint_matches_upstream_path_and_method
    endpoint = BetterAuth::Stripe::Routes::SubscriptionSuccess.endpoint({})

    assert_equal "/subscription/success", endpoint.path
    assert_equal ["GET"], endpoint.methods
  end

  def test_cancel_callback_endpoint_matches_upstream_path_and_method
    endpoint = BetterAuth::Stripe::Routes::CancelSubscriptionCallback.endpoint({})

    assert_equal "/subscription/cancel/callback", endpoint.path
    assert_equal ["GET"], endpoint.methods
  end
end
