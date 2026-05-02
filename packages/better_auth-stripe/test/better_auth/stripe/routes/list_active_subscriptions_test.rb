# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthStripeRoutesListActiveSubscriptionsTest < Minitest::Test
  def test_endpoint_matches_upstream_path_and_method
    endpoint = BetterAuth::Stripe::Routes::ListActiveSubscriptions.endpoint({})

    assert_equal "/subscription/list", endpoint.path
    assert_equal ["GET"], endpoint.methods
  end
end
