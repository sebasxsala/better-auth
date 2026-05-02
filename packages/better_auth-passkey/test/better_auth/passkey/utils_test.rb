# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPasskeyUtilsTest < Minitest::Test
  def test_rp_id_prefers_explicit_config
    assert_equal "explicit.example", BetterAuth::Passkey::Utils.rp_id({rp_id: "explicit.example"}, ctx("https://ignored.example"))
  end

  def test_rp_id_uses_base_url_hostname_without_port
    assert_equal "example.com", BetterAuth::Passkey::Utils.rp_id({}, ctx("https://example.com:8443/api/auth"))
  end

  def test_rp_id_defaults_to_localhost_without_base_url
    assert_equal "localhost", BetterAuth::Passkey::Utils.rp_id({}, ctx(nil))
  end

  def test_rp_id_falls_back_to_localhost_for_invalid_ruby_base_url
    assert_equal "localhost", BetterAuth::Passkey::Utils.rp_id({}, ctx("not a url"))
  end

  def test_legacy_private_plugin_rp_id_delegates_to_utils
    assert_equal "example.com", BetterAuth::Plugins.send(:passkey_rp_id, {}, ctx("https://example.com:8443/api/auth"))
  end

  private

  def ctx(base_url)
    options = Struct.new(:base_url).new(base_url)
    context = Struct.new(:options, :app_name).new(options, "Test App")
    Struct.new(:context).new(context)
  end
end
