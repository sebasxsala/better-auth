# frozen_string_literal: true

require "jwt"
require "rack/mock"
require_relative "../../test_helper"

class BetterAuthPluginsOIDCProviderTest < Minitest::Test
  SECRET = "phase-eleven-secret-with-enough-entropy-123"

  def test_parse_prompt_matches_upstream_rules
    assert_equal ["login"], BetterAuth::Plugins::OIDCProvider.parse_prompt("login").to_a
    assert_equal ["login", "consent"], BetterAuth::Plugins::OIDCProvider.parse_prompt(" login   consent ").to_a
    assert_equal [], BetterAuth::Plugins::OIDCProvider.parse_prompt("unknown").to_a

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins::OIDCProvider.parse_prompt("none consent")
    end
    assert_equal "invalid_request", error.message
  end

  def test_metadata_registration_authorization_token_and_userinfo_flow
    auth = build_auth
    cookie = sign_up_cookie(auth)

    metadata = auth.api.get_open_id_config
    assert_equal "http://localhost:3000", metadata[:issuer]
    assert_equal "http://localhost:3000/api/auth/oauth2/authorize", metadata[:authorization_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/token", metadata[:token_endpoint]
    assert_includes metadata[:scopes_supported], "openid"

    client = auth.api.register_o_auth_application(
      body: {
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        skip_consent: true,
        client_name: "Ruby Client"
      }
    )
    assert_equal "none", client[:token_endpoint_auth_method]
    assert_nil client[:client_secret]

    status, headers, _body = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://client.example/callback",
        scope: "openid email profile offline_access",
        state: "state-123",
        prompt: "none"
      },
      as_response: true
    )
    assert_equal 302, status
    redirect = URI.parse(headers.fetch("location"))
    redirect_params = Rack::Utils.parse_query(redirect.query)
    assert_equal "state-123", redirect_params["state"]
    assert_equal "http://localhost:3000", redirect_params["iss"]
    assert redirect_params["code"]

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: redirect_params.fetch("code"),
        redirect_uri: "https://client.example/callback",
        client_id: client[:client_id]
      }
    )
    assert_equal "Bearer", tokens[:token_type]
    assert tokens[:access_token]
    assert tokens[:id_token]
    assert tokens[:refresh_token]

    userinfo = auth.api.o_auth2_user_info(headers: {"authorization" => "Bearer #{tokens[:access_token]}"})
    assert_equal "oidc@example.com", userinfo[:email]
    assert_equal false, userinfo[:email_verified]
    assert_equal "OIDC User", userinfo[:name]
  end

  def test_logout_endpoint_clears_session_and_redirects_to_registered_url
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_application(
      body: {
        redirect_uris: ["https://client.example/callback"],
        post_logout_redirect_uris: ["https://client.example/logout"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Logout Client"
      }
    )

    status, headers, _body = auth.api.end_session(
      headers: {"cookie" => cookie},
      query: {
        client_id: client[:client_id],
        post_logout_redirect_uri: "https://client.example/logout",
        state: "bye"
      },
      as_response: true
    )

    assert_equal 302, status
    assert_equal "https://client.example/logout?state=bye", headers.fetch("location")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token=;"
  end

  def test_authorization_prompt_consent_records_consent_before_issuing_code
    auth = build_auth(consent_page: "/oidc/consent")
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_application(
      body: {
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Consent Client"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://client.example/callback",
        scope: "openid email",
        state: "consent-state",
        prompt: "consent"
      },
      as_response: true
    )
    assert_equal 302, status
    consent_redirect = URI.parse(headers.fetch("location"))
    assert_equal "/oidc/consent", consent_redirect.path
    consent_code = Rack::Utils.parse_query(consent_redirect.query).fetch("consent_code")

    consent = auth.api.o_auth_consent(headers: {"cookie" => cookie}, body: {accept: true, consent_code: consent_code})
    callback = URI.parse(consent.fetch(:redirectURI))
    params = Rack::Utils.parse_query(callback.query)
    assert_equal "consent-state", params.fetch("state")
    assert params.fetch("code")

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: params.fetch("code"),
        redirect_uri: "https://client.example/callback",
        client_id: client[:client_id]
      }
    )
    assert tokens[:id_token]
    assert_equal "openid email", tokens[:scope]
  end

  def test_prompt_none_returns_consent_required_when_consent_is_missing
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_application(
      body: {
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Prompt None Client"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://client.example/callback",
        scope: "openid email",
        state: "state-missing-consent",
        prompt: "none"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "consent_required", params.fetch("error")
    assert_equal "state-missing-consent", params.fetch("state")
  end

  private

  def build_auth(options = {})
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.oidc_provider(options)]
    )
  end

  def sign_up_cookie(auth)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "oidc@example.com", password: "password123", name: "OIDC User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
