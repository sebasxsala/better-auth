# frozen_string_literal: true

require "json"
require "rack/mock"
require_relative "../test_helper"

class BetterAuthPluginsSSOOIDCTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_oidc_discovery_normalizes_and_validates_document
    discovery = BetterAuth::Plugins.sso_discover_oidc_config(
      issuer: "https://idp.example.com",
      fetch: ->(_url) {
        {
          issuer: "https://idp.example.com",
          authorization_endpoint: "https://idp.example.com/authorize",
          token_endpoint: "https://idp.example.com/token",
          userinfo_endpoint: "https://idp.example.com/userinfo",
          jwks_uri: "https://idp.example.com/jwks"
        }
      }
    )

    assert_equal "https://idp.example.com/authorize", discovery.fetch(:authorization_endpoint)
    assert_equal "https://idp.example.com/token", discovery.fetch(:token_endpoint)

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_discover_oidc_config(
        issuer: "https://idp.example.com",
        fetch: ->(_url) { {issuer: "https://wrong.example.com"} }
      )
    end
    assert_equal 400, error.status_code
    assert_equal "Invalid OIDC discovery document", error.message
  end

  def test_oidc_discovery_hydrates_relative_urls_and_selects_auth_method
    discovery = BetterAuth::Plugins.sso_discover_oidc_config(
      issuer: "https://idp.example.com/tenant",
      existing_config: {clientId: "configured", tokenEndpointAuthentication: "client_secret_post"},
      trusted_origin: ->(url) { url.start_with?("https://idp.example.com") },
      fetch: ->(url) {
        assert_equal "https://idp.example.com/tenant/.well-known/openid-configuration", url
        {
          issuer: "https://idp.example.com/tenant",
          authorization_endpoint: "/tenant/authorize",
          token_endpoint: "/tenant/token",
          jwks_uri: "/tenant/jwks",
          userinfo_endpoint: "/tenant/userinfo",
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          scopes_supported: ["openid", "email"]
        }
      }
    )

    assert_equal "configured", discovery.fetch(:client_id)
    assert_equal "client_secret_post", discovery.fetch(:token_endpoint_authentication)
    assert_equal "https://idp.example.com/tenant/authorize", discovery.fetch(:authorization_endpoint)
    assert_equal "https://idp.example.com/tenant/jwks", discovery.fetch(:jwks_endpoint)
    assert_equal ["openid", "email"], discovery.fetch(:scopes_supported)
  end

  def test_oidc_discovery_rejects_untrusted_discovered_urls
    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_discover_oidc_config(
        issuer: "https://idp.example.com",
        trusted_origin: ->(url) { url.start_with?("https://idp.example.com") },
        fetch: ->(_url) {
          {
            issuer: "https://idp.example.com",
            authorization_endpoint: "https://evil.example.com/authorize",
            token_endpoint: "https://idp.example.com/token",
            jwks_uri: "https://idp.example.com/jwks"
          }
        }
      )
    end

    assert_equal 400, error.status_code
    assert_equal "OIDC discovery endpoint is not trusted", error.message
  end

  def test_oidc_callback_creates_user_session_and_rejects_invalid_state
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "example.com",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          userInfoEndpoint: "https://idp.example.com/userinfo",
          getToken: ->(code:, **_data) {
            raise "unexpected code" unless code == "good-code"

            {accessToken: "access-token", idToken: "id-token"}
          },
          getUserInfo: ->(_tokens) { {id: "oidc-sub", email: "oidc@example.com", name: "OIDC User", emailVerified: true} }
        }
      }
    )
    sign_in = auth.api.sign_in_sso(body: {providerId: "oidc", callbackURL: "/dashboard", newUserCallbackURL: "/welcome"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")

    status, headers, _body = auth.api.callback_sso(
      params: {providerId: "oidc"},
      query: {code: "good-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/welcome", headers.fetch("location")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    user = auth.context.internal_adapter.find_user_by_email("oidc@example.com")[:user]
    assert_equal "OIDC User", user.fetch("name")

    invalid = auth.api.callback_sso(
      params: {providerId: "oidc"},
      query: {code: "good-code", state: "bad"},
      as_response: true
    )
    assert_equal 302, invalid.first
    assert_includes invalid[1].fetch("location"), "error=invalid_state"
  end

  private

  def build_auth
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.sso]
    )
  end

  def sign_up_cookie(auth)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "owner@example.com", password: "password123", name: "Owner"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
