# frozen_string_literal: true

require_relative "../../test_helper"

class APIKeyExternalPluginShimTest < Minitest::Test
  def test_api_key_shim_has_helpful_error_when_external_package_is_missing
    error = assert_raises(LoadError) do
      BetterAuth::Plugins.api_key
    end

    assert_includes error.message, "better_auth-api-key"
    assert_includes error.message, "require \"better_auth/api_key\""
  end
end
