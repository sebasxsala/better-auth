# frozen_string_literal: true

require_relative "../../test_helper"

class ExternalPluginShimTest < Minitest::Test
  def test_sso_shim_has_helpful_error_when_external_package_is_missing
    error = assert_raises(LoadError) do
      BetterAuth::Plugins.sso
    end

    assert_includes error.message, "better_auth-sso"
    assert_includes error.message, "require \"better_auth/sso\""
  end

  def test_scim_shim_has_helpful_error_when_external_package_is_missing
    error = assert_raises(LoadError) do
      BetterAuth::Plugins.scim
    end

    assert_includes error.message, "better_auth-scim"
    assert_includes error.message, "require \"better_auth/scim\""
  end

  def test_passkey_shim_has_helpful_error_when_external_package_is_missing
    error = assert_raises(LoadError) do
      BetterAuth::Plugins.passkey
    end

    assert_includes error.message, "better_auth-passkey"
    assert_includes error.message, "require \"better_auth/passkey\""
  end

  def test_oauth_provider_shim_has_helpful_error_when_external_package_is_missing
    error = assert_raises(LoadError) do
      BetterAuth::Plugins.oauth_provider
    end

    assert_includes error.message, "better_auth-oauth-provider"
    assert_includes error.message, "require \"better_auth/oauth_provider\""
  end

  def test_api_key_shim_has_helpful_error_when_external_package_is_missing
    error = assert_raises(LoadError) do
      BetterAuth::Plugins.api_key
    end

    assert_includes error.message, "better_auth-api-key"
    assert_includes error.message, "require \"better_auth/api_key\""
  end
end
