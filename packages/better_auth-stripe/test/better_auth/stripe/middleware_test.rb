# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthStripeMiddlewareTest < Minitest::Test
  def test_customer_type_defaults_to_user_and_accepts_camel_case
    assert_equal "user", BetterAuth::Stripe::Middleware.customer_type!({})
    assert_equal "organization", BetterAuth::Stripe::Middleware.customer_type!({customerType: "organization"})
  end

  def test_customer_type_rejects_unknown_values
    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Stripe::Middleware.customer_type!({customer_type: "workspace"})
    end

    assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("INVALID_CUSTOMER_TYPE"), error.message
  end

  def test_reference_id_uses_user_for_user_customer_type
    session = {
      user: {"id" => "user_123"},
      session: {"activeOrganizationId" => "org_123"}
    }

    assert_equal "user_123", BetterAuth::Stripe::Middleware.reference_id!(nil, session, "user", nil, {})
    assert_equal "custom_ref", BetterAuth::Stripe::Middleware.reference_id!(nil, session, "user", "custom_ref", {})
  end

  def test_reference_id_requires_enabled_organization_subscriptions
    session = {
      user: {"id" => "user_123"},
      session: {"activeOrganizationId" => "org_123"}
    }

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Stripe::Middleware.reference_id!(nil, session, "organization", nil, {})
    end

    assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("ORGANIZATION_SUBSCRIPTION_NOT_ENABLED"), error.message
  end

  def test_authorize_reference_allows_own_user_reference_without_callback
    session = {
      user: {"id" => "user_123"},
      session: {"id" => "session_123"}
    }

    assert_nil BetterAuth::Stripe::Middleware.authorize_reference!(nil, session, "user_123", "upgrade-subscription", "user", {}, explicit: false)
  end
end
