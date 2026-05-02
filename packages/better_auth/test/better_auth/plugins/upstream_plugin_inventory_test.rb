# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPluginsUpstreamInventoryTest < Minitest::Test
  def test_upstream_hook_only_plugins_do_not_register_http_endpoints
    plugins = [
      BetterAuth::Plugins.additional_fields(user: {plan: {type: "string", required: false}}),
      BetterAuth::Plugins.bearer,
      BetterAuth::Plugins.captcha(provider: "cloudflare-turnstile", secret_key: "captcha-secret"),
      BetterAuth::Plugins.have_i_been_pwned,
      BetterAuth::Plugins.last_login_method
    ]

    plugins.each do |plugin|
      assert_empty plugin.endpoints, "#{plugin.id} should not register its own HTTP endpoints"
    end
  end

  def test_access_matches_upstream_helper_surface_not_plugin_endpoint_surface
    access_control = BetterAuth::Plugins.create_access_control(project: ["read"])

    assert_equal({success: true}, access_control.new_role(project: ["read"]).authorize(project: ["read"]))
    refute_respond_to access_control, :endpoints
  end
end
