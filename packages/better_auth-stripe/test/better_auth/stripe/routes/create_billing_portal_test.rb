# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthStripeRoutesCreateBillingPortalTest < Minitest::Test
  def test_endpoint_matches_upstream_path_and_method
    endpoint = BetterAuth::Stripe::Routes::CreateBillingPortal.endpoint({})

    assert_equal "/subscription/billing-portal", endpoint.path
    assert_equal ["POST"], endpoint.methods
  end
end
