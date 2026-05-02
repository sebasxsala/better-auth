# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthStripeRoutesCancelSubscriptionTest < Minitest::Test
  def test_endpoint_matches_upstream_path_and_method
    endpoint = BetterAuth::Stripe::Routes::CancelSubscription.endpoint({})

    assert_equal "/subscription/cancel", endpoint.path
    assert_equal ["POST"], endpoint.methods
  end
end
