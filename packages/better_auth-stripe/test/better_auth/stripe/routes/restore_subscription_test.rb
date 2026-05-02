# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthStripeRoutesRestoreSubscriptionTest < Minitest::Test
  def test_endpoint_matches_upstream_path_and_method
    endpoint = BetterAuth::Stripe::Routes::RestoreSubscription.endpoint({})

    assert_equal "/subscription/restore", endpoint.path
    assert_equal ["POST"], endpoint.methods
  end
end
