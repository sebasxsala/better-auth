# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthStripeSchemaTest < Minitest::Test
  def test_base_schema_includes_user_stripe_customer_id
    schema = BetterAuth::Stripe::Schema.schema({})

    assert_equal({type: "string", required: false}, schema.fetch(:user).fetch(:fields).fetch(:stripeCustomerId))
    refute schema.key?(:subscription)
  end

  def test_subscription_schema_includes_upstream_fields
    schema = BetterAuth::Stripe::Schema.schema(subscription: {enabled: true, plans: []})
    fields = schema.fetch(:subscription).fetch(:fields)

    assert_equal({type: "string", required: false}, fields.fetch(:billingInterval))
    assert_equal({type: "string", required: false}, fields.fetch(:stripeScheduleId))
  end

  def test_organization_schema_is_conditional
    schema = BetterAuth::Stripe::Schema.schema(organization: {enabled: true})

    assert_equal({type: "string", required: false}, schema.fetch(:organization).fetch(:fields).fetch(:stripeCustomerId))
  end

  def test_custom_subscription_schema_is_ignored_when_subscriptions_are_disabled
    schema = BetterAuth::Stripe::Schema.schema(
      schema: {
        user: {fields: {role: {type: "string", required: false}}},
        subscription: {fields: {custom: {type: "string", required: false}}}
      }
    )

    assert_equal({type: "string", required: false}, schema.fetch(:user).fetch(:fields).fetch(:role))
    refute schema.key?(:subscription)
  end
end
