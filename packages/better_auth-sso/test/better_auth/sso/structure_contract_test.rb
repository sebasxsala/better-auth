# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthSSOStructureContractTest < Minitest::Test
  Constants = BetterAuth::SSO::Constants
  Types = BetterAuth::SSO::Types
  OIDC = BetterAuth::SSO::OIDC
  Discovery = BetterAuth::SSO::OIDC::Discovery
  OIDCTypes = BetterAuth::SSO::OIDC::Types
  Errors = BetterAuth::SSO::OIDC::Errors
  DiscoveryError = BetterAuth::SSO::OIDC::DiscoveryError

  def test_constants_mirror_plugin_storage_and_ttl_contract
    assert_equal "saml-authn-request:", Constants::AUTHN_REQUEST_KEY_PREFIX
    assert_equal "saml-used-assertion:", Constants::USED_ASSERTION_KEY_PREFIX
    assert_equal "saml-session:", Constants::SAML_SESSION_KEY_PREFIX
    assert_equal "saml-session-by-id:", Constants::SAML_SESSION_BY_ID_PREFIX
    assert_equal "saml-logout-request:", Constants::LOGOUT_REQUEST_KEY_PREFIX
    assert_equal 5 * 60 * 1000, Constants::DEFAULT_AUTHN_REQUEST_TTL_MS
    assert_equal 15 * 60 * 1000, Constants::DEFAULT_ASSERTION_TTL_MS
    assert_equal 5 * 60 * 1000, Constants::DEFAULT_LOGOUT_REQUEST_TTL_MS
    assert_equal 5 * 60 * 1000, Constants::DEFAULT_CLOCK_SKEW_MS
    assert_equal 256 * 1024, Constants::DEFAULT_MAX_SAML_RESPONSE_SIZE
    assert_equal 100 * 1024, Constants::DEFAULT_MAX_SAML_METADATA_SIZE
    assert_equal "urn:oasis:names:tc:SAML:2.0:status:Success", Constants::SAML_STATUS_SUCCESS
  end

  def test_type_helpers_accept_upstream_strings_and_ruby_symbols
    assert_equal %w[oidc saml], Types::PROVIDER_TYPES
    assert Types::PROVIDER_TYPES.frozen?
    assert Types.provider_type?("oidc")
    assert Types.provider_type?(:saml)
    refute Types.provider_type?("oauth")
    refute Types.provider_type?(nil)

    assert_equal %w[client_secret_post client_secret_basic], Types::OIDC_TOKEN_ENDPOINT_AUTH_METHODS
    assert Types::OIDC_TOKEN_ENDPOINT_AUTH_METHODS.frozen?
    assert Types.oidc_token_endpoint_auth_method?("client_secret_basic")
    assert Types.oidc_token_endpoint_auth_method?(:client_secret_post)
    refute Types.oidc_token_endpoint_auth_method?("private_key_jwt")
    refute Types.oidc_token_endpoint_auth_method?(nil)
  end

  def test_linking_normalized_profile_accepts_upstream_and_ruby_keys
    upstream_profile = BetterAuth::SSO::Linking.normalized_profile(
      "providerType" => "saml",
      "providerId" => "saml-provider",
      "accountId" => "account-1",
      "email" => "ALICE@EXAMPLE.COM",
      "emailVerified" => true,
      "rawAttributes" => {"department" => "engineering"}
    )

    assert_equal "saml", upstream_profile.fetch(:provider_type)
    assert_equal "saml-provider", upstream_profile.fetch(:provider_id)
    assert_equal "account-1", upstream_profile.fetch(:account_id)
    assert_equal "alice@example.com", upstream_profile.fetch(:email)
    assert_equal true, upstream_profile.fetch(:email_verified)
    assert_equal({"department" => "engineering"}, upstream_profile.fetch(:raw_attributes))

    ruby_profile = BetterAuth::SSO::Linking.normalized_profile(
      provider_type: :oidc,
      provider_id: "oidc-provider",
      account_id: "account-2",
      email: "bob@example.com",
      email_verified: false
    )

    assert_equal "oidc", ruby_profile.fetch(:provider_type)
    assert_equal false, ruby_profile.fetch(:email_verified)
  end

  def test_linking_normalized_profile_rejects_missing_required_fields
    error = assert_raises(ArgumentError) do
      BetterAuth::SSO::Linking.normalized_profile(providerType: "saml", email: "alice@example.com")
    end

    assert_match(/providerId/, error.message)
  end

  def test_oidc_public_wrapper_exposes_discovery_contract
    result = OIDC.discover_config(
      issuer: "https://idp.example.com",
      fetch: ->(_url, **_options) {
        {
          issuer: "https://idp.example.com",
          authorization_endpoint: "/authorize",
          token_endpoint: "/token",
          jwks_uri: "/jwks",
          token_endpoint_auth_methods_supported: ["client_secret_post"]
        }
      },
      trusted_origin: ->(url) { url.start_with?("https://idp.example.com/") },
      existing_config: {
        client_id: "client-id",
        client_secret: "client-secret"
      }
    )

    assert_equal "https://idp.example.com/.well-known/openid-configuration", result.fetch(:discovery_endpoint)
    assert_equal "https://idp.example.com/authorize", result.fetch(:authorization_endpoint)
    assert_equal "https://idp.example.com/token", result.fetch(:token_endpoint)
    assert_equal "https://idp.example.com/jwks", result.fetch(:jwks_endpoint)
    assert_equal "client_secret_post", result.fetch(:token_endpoint_authentication)
    assert_equal "client-id", result.fetch(:client_id)
    assert_equal "client-secret", result.fetch(:client_secret)

    assert OIDC.needs_runtime_discovery?(authorization_endpoint: "https://idp.example.com/authorize")
    refute OIDC.needs_runtime_discovery?(
      authorization_endpoint: "https://idp.example.com/authorize",
      token_endpoint: "https://idp.example.com/token",
      jwks_endpoint: "https://idp.example.com/jwks"
    )
  end

  def test_oidc_error_surface_preserves_discovery_metadata_and_maps_api_errors
    discovery_error = DiscoveryError.new(
      "discovery_invalid_url",
      "The url \"discoveryEndpoint\" must be valid",
      details: {url: "not-a-url"}
    )

    assert_equal "discovery_invalid_url", discovery_error.code
    assert_equal({url: "not-a-url"}, discovery_error.details)

    api_error = Errors.api_error(discovery_error)
    assert_instance_of BetterAuth::APIError, api_error
    assert_equal "BAD_REQUEST", api_error.status
    assert_equal 400, api_error.status_code
    assert_equal discovery_error.message, api_error.message

    existing_api_error = BetterAuth::APIError.new("BAD_GATEWAY", message: "upstream failed")
    assert_same existing_api_error, Errors.api_error(existing_api_error)
  end

  def test_discovery_required_field_constants_match_upstream_oidc_types
    assert_equal %i[issuer authorization_endpoint token_endpoint jwks_uri], Discovery::REQUIRED_DISCOVERY_FIELDS
    assert Discovery::REQUIRED_DISCOVERY_FIELDS.frozen?
    assert_equal Discovery::REQUIRED_DISCOVERY_FIELDS, OIDCTypes::REQUIRED_DISCOVERY_FIELDS
    assert_includes OIDCTypes::DISCOVERY_ERROR_CODES, "discovery_timeout"
    assert_includes OIDCTypes::DISCOVERY_ERROR_CODES, "unsupported_token_auth_method"
    assert OIDCTypes.discovery_error_code?("issuer_mismatch")
    refute OIDCTypes.discovery_error_code?("unknown")
  end

  def test_saml_index_reexports_algorithm_and_assertion_helpers
    assert_respond_to BetterAuth::SSO::SAML, :validate_config_algorithms
    assert_respond_to BetterAuth::SSO::SAML, :validate_saml_algorithms
    assert_respond_to BetterAuth::SSO::SAML, :validate_single_assertion

    assert_equal true, BetterAuth::SSO::SAML.validate_config_algorithms({})
  end
end
