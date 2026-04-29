# frozen_string_literal: true

require_relative "../../test_helper"

class ExternalPluginShimTest < Minitest::Test
  def test_sso_shim_has_helpful_error_when_external_package_is_missing
    assert_external_plugin_shim(:sso, "better_auth-sso", "better_auth/sso")
  end

  def test_scim_shim_has_helpful_error_when_external_package_is_missing
    assert_external_plugin_shim(:scim, "better_auth-scim", "better_auth/scim")
  end

  def test_passkey_shim_has_helpful_error_when_external_package_is_missing
    assert_external_plugin_shim(:passkey, "better_auth-passkey", "better_auth/passkey")
  end

  def test_oauth_provider_shim_has_helpful_error_when_external_package_is_missing
    assert_external_plugin_shim(:oauth_provider, "better_auth-oauth-provider", "better_auth/oauth_provider")
  end

  def test_api_key_shim_has_helpful_error_when_external_package_is_missing
    assert_external_plugin_shim(:api_key, "better_auth-api-key", "better_auth/api_key")
  end

  private

  def assert_external_plugin_shim(method_name, gem_name, require_path)
    original_require = Kernel.method(:require)
    missing_require = lambda do |path|
      raise LoadError, "cannot load such file -- #{path}" if path == require_path

      original_require.call(path)
    end

    error = assert_raises(LoadError) do
      Kernel.stub(:require, missing_require) do
        BetterAuth::Plugins.public_send(method_name)
      end
    end

    assert_includes error.message, gem_name
    assert_includes error.message, "require \"#{require_path}\""
  end
end
