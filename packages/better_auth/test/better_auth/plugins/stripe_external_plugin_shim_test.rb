# frozen_string_literal: true

require_relative "../../test_helper"

class StripeExternalPluginShimTest < Minitest::Test
  def test_stripe_shim_has_helpful_error_when_external_package_is_missing
    error = assert_raises(LoadError) do
      BetterAuth::Plugins.stripe
    end

    assert_includes error.message, "better_auth-stripe"
    assert_includes error.message, "require \"better_auth/stripe\""
  end
end
