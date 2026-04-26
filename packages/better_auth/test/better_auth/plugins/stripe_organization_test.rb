# frozen_string_literal: true

require_relative "stripe_test"

class BetterAuthPluginsStripeOrganizationTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_organization_customer_schema_is_guarded_until_organization_plugin_exists
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.stripe(
          stripe_client: BetterAuthPluginsStripeTest::FakeStripeClient.new,
          organization: {enabled: true},
          subscription: {enabled: true, plans: [{name: "team", price_id: "price_team"}]}
        )
      ]
    )

    assert auth.context.schema.fetch("organization").fetch(:fields).key?("stripeCustomerId")
    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(body: {plan: "team", customerType: "organization", referenceId: "org-1", successUrl: "http://localhost:3000/s", cancelUrl: "http://localhost:3000/c"})
    end
    assert_equal 400, error.status_code
    assert_equal "Organization integration requires the organization plugin", error.message
  end
end
