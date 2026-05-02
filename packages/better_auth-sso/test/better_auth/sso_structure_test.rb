# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthSSOStructureTest < Minitest::Test
  def test_upstream_shaped_modules_load
    assert defined?(BetterAuth::SSO::Constants)
    assert defined?(BetterAuth::SSO::Client)
    assert defined?(BetterAuth::SSO::Types)
    assert defined?(BetterAuth::SSO::Utils)
    assert defined?(BetterAuth::SSO::DomainVerification)
    assert defined?(BetterAuth::SSO::OIDC)
    assert defined?(BetterAuth::SSO::OIDC::Discovery)
    assert defined?(BetterAuth::SSO::OIDC::Types)
    assert defined?(BetterAuth::SSO::Linking)
    assert defined?(BetterAuth::SSO::Linking::Types)
    assert defined?(BetterAuth::SSO::Routes::Schemas)
    assert defined?(BetterAuth::SSO::Routes::Providers)
    assert defined?(BetterAuth::SSO::Routes::Helpers)
    assert defined?(BetterAuth::SSO::Routes::SAMLPipeline)
    assert defined?(BetterAuth::SSO::SAML::Algorithms)
    assert defined?(BetterAuth::SSO::SAML::Assertions)
    assert defined?(BetterAuth::SSO::SAML::ErrorCodes)
    assert defined?(BetterAuth::SSO::SAML::Parser)
    assert defined?(BetterAuth::SSO::SAML::Timestamp)
    assert defined?(BetterAuth::SSO::SAMLState)
    assert_respond_to BetterAuth::SSO::SAMLState, :generate_relay_state
    assert_respond_to BetterAuth::SSO::SAMLState, :parse_relay_state
  end

  def test_client_contract_matches_upstream_client_plugin_shape
    client = BetterAuth::SSO::Client.sso_client

    assert_equal "sso-client", client.fetch(:id)
    assert_equal BetterAuth::SSO::PACKAGE_VERSION, client.fetch(:version)
    assert_equal BetterAuth::SSO::VERSION, client.fetch(:version)
    assert_equal({"/sso/providers" => "GET", "/sso/get-provider" => "GET"}, client.fetch(:path_methods))
    assert_equal({domain_verification: {enabled: false}}, client.fetch(:infer_server_plugin))

    enabled_client = BetterAuth::SSO::Client.sso_client(domain_verification: {enabled: true})
    assert_equal({domain_verification: {enabled: true}}, enabled_client.fetch(:infer_server_plugin))
  end

  def test_type_helpers_match_upstream_provider_enums
    assert BetterAuth::SSO::Types.provider_type?("oidc")
    assert BetterAuth::SSO::Types.provider_type?("saml")
    refute BetterAuth::SSO::Types.provider_type?("password")

    assert BetterAuth::SSO::Types.oidc_token_endpoint_auth_method?("client_secret_post")
    assert BetterAuth::SSO::Types.oidc_token_endpoint_auth_method?("client_secret_basic")
    refute BetterAuth::SSO::Types.oidc_token_endpoint_auth_method?("private_key_jwt")
  end

  def test_schema_key_helpers_accept_ruby_and_upstream_names
    assert BetterAuth::SSO::Routes::Schemas.oidc_config_key?(:client_id)
    assert BetterAuth::SSO::Routes::Schemas.oidc_config_key?("clientId")
    assert BetterAuth::SSO::Routes::Schemas.saml_config_key?(:entry_point)
    assert BetterAuth::SSO::Routes::Schemas.saml_config_key?("entryPoint")
    assert BetterAuth::SSO::Routes::Schemas.saml_config_key?("wantLogoutRequestSigned")
    refute BetterAuth::SSO::Routes::Schemas.saml_config_key?("unknown")
  end

  def test_saml_error_codes_match_upstream_names
    assert_equal "Single Logout is not enabled", BetterAuth::SSO::SAML::ErrorCodes.message(:single_logout_not_enabled)
    assert_equal "Invalid LogoutResponse", BetterAuth::SSO::SAML::ErrorCodes.message("invalidLogoutResponse")
    assert_equal "SAML provider not found", BetterAuth::SSO::SAML::ErrorCodes.message("samlProviderNotFound")
  end
end
