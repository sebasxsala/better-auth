# frozen_string_literal: true

require_relative "test_support"

class BetterAuthAPIKeyPluginTest < Minitest::Test
  include APIKeyTestSupport

  def test_public_plugin_metadata_matches_upstream_entrypoint
    plugin = BetterAuth::Plugins.api_key

    assert_equal "api-key", plugin.id
    assert_equal BetterAuth::APIKey::VERSION, plugin.version
    assert_equal BetterAuth::APIKey::ERROR_CODES, plugin.error_codes
    assert_equal BetterAuth::APIKey::ERROR_CODES, BetterAuth::Plugins::API_KEY_ERROR_CODES
    assert_equal "apikey", BetterAuth::Plugins::API_KEY_TABLE_NAME
  end

  def test_plugin_factory_builds_same_public_contract
    plugin = BetterAuth::APIKey::PluginFactory.build(default_key_length: 12)

    assert_equal "api-key", plugin.id
    assert_equal BetterAuth::APIKey::VERSION, plugin.version
    assert_equal BetterAuth::APIKey::ERROR_CODES, plugin.error_codes
    assert_equal %i[
      create_api_key
      verify_api_key
      get_api_key
      update_api_key
      delete_api_key
      list_api_keys
      delete_all_expired_api_keys
    ].sort, plugin.endpoints.keys.sort
    assert_equal 12, plugin.options[:default_key_length]
  end

  def test_default_key_hasher_matches_sha256_base64url_contract
    assert_equal BetterAuth::Crypto.sha256("api-key-value", encoding: :base64url),
      BetterAuth::Plugins.default_api_key_hasher("api-key-value")
  end

  def test_api_key_session_hook_uses_configured_header
    auth = build_api_key_auth(api_key_headers: ["x-custom-api-key"], enable_session_for_api_keys: true, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "plugin-session-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    assert_nil auth.api.get_session(headers: {"x-api-key" => created[:key]})

    session = auth.api.get_session(headers: {"x-custom-api-key" => created[:key]})
    assert_equal "plugin-session-key@example.com", session[:user]["email"]
  end
end
