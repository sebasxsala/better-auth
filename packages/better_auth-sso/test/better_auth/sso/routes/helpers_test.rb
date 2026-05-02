# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthSSORoutesHelpersTest < Minitest::Test
  ROUTES = BetterAuth::SSO::Routes::Helpers

  def test_find_saml_provider_delegates_to_plugins
    ctx = Object.new
    provider = {"providerId" => "saml-provider"}
    calls = []

    BetterAuth::Plugins.stub(:sso_find_provider!, ->(*args) {
      calls << args
      provider
    }) do
      assert_same provider, ROUTES.find_saml_provider!(ctx, "saml-provider")
    end

    assert_equal [[ctx, "saml-provider"]], calls
  end

  def test_create_saml_post_form_delegates_to_plugins
    response = Object.new
    calls = []

    BetterAuth::Plugins.stub(:sso_saml_post_form, ->(*args) {
      calls << args
      response
    }) do
      assert_same response, ROUTES.create_saml_post_form(
        "https://idp.example.com/sso",
        "SAMLRequest",
        "encoded-request",
        "relay-state"
      )
    end

    assert_equal [
      [
        "https://idp.example.com/sso",
        "SAMLRequest",
        "encoded-request",
        "relay-state"
      ]
    ], calls
  end
end
