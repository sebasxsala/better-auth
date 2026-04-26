# frozen_string_literal: true

require "json"
require "rack/mock"
require_relative "../../test_helper"

class BetterAuthPluginsGenericOAuthTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"

  def test_sign_in_oauth2_generates_authorization_url_with_state_and_scopes
    auth = build_auth

    result = auth.api.sign_in_with_oauth2(
      body: {
        providerId: "custom",
        callbackURL: "/dashboard",
        newUserCallbackURL: "/welcome",
        scopes: ["calendar"],
        disableRedirect: true
      }
    )
    uri = URI.parse(result[:url])
    params = Rack::Utils.parse_query(uri.query)

    assert_equal false, result[:redirect]
    assert_equal "https", uri.scheme
    assert_equal "provider.example.com", uri.host
    assert_equal "/authorize", uri.path
    assert_equal "client-id", params["client_id"]
    assert_equal "code", params["response_type"]
    assert_equal "calendar profile email", params["scope"]
    assert_equal "http://localhost:3000/api/auth/oauth2/callback/custom", params["redirect_uri"]
    assert params["state"]
  end

  def test_callback_creates_user_account_session_and_redirects_new_user
    auth = build_auth
    sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard", newUserCallbackURL: "/welcome"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")

    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/welcome", headers.fetch("location")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    user = auth.context.internal_adapter.find_user_by_email("oauth@example.com")[:user]
    account = auth.context.internal_adapter.find_account_by_provider_id("oauth-sub", "custom")
    assert_equal user["id"], account["userId"]
    assert_equal "access-token", account["accessToken"]
    assert_equal "refresh-token", account["refreshToken"]
    assert_equal "openid,email", account["scope"]
  end

  def test_callback_reuses_existing_user_and_honors_disable_implicit_sign_up
    disabled = build_auth(disable_implicit_sign_up: true)
    sign_in = disabled.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard", errorCallbackURL: "/error"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")
    status, headers, _body = disabled.api.o_auth2_callback(params: {providerId: "custom"}, query: {code: "oauth-code", state: state}, as_response: true)

    assert_equal 302, status
    assert_equal "/error?error=signup_disabled", headers.fetch("location")

    requested = build_auth(disable_implicit_sign_up: true)
    sign_in = requested.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard", errorCallbackURL: "/error", requestSignUp: true})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")
    status, headers, _body = requested.api.o_auth2_callback(params: {providerId: "custom"}, query: {code: "oauth-code", state: state}, as_response: true)

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
  end

  def test_link_account_generates_link_state_and_callback_links_to_current_user
    auth = build_auth(user_info: {id: "linked-sub", email: "link@example.com", name: "Linked User"})
    cookie = sign_up_cookie(auth, email: "link@example.com")
    link = auth.api.o_auth2_link_account(
      headers: {"cookie" => cookie},
      body: {providerId: "custom", callbackURL: "/settings", scopes: ["files"]}
    )
    state = Rack::Utils.parse_query(URI.parse(link[:url]).query).fetch("state")

    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/settings", headers.fetch("location")
    user = auth.context.internal_adapter.find_user_by_email("link@example.com")[:user]
    account = auth.context.internal_adapter.find_account_by_provider_id("linked-sub", "custom")
    assert_equal user["id"], account["userId"]
  end

  def test_invalid_provider_and_issuer_mismatch_errors
    auth = build_auth

    provider_error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_with_oauth2(body: {providerId: "missing"})
    end
    assert_equal 400, provider_error.status_code
    assert_equal "No config found for provider missing", provider_error.message

    sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", errorCallbackURL: "/error"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")
    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state, iss: "https://wrong.example.com"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/error?error=issuer_mismatch", headers.fetch("location")
  end

  private

  def build_auth(options = {})
    user_info = options.delete(:user_info) || {id: "oauth-sub", email: "oauth@example.com", name: "OAuth User", emailVerified: true, image: "https://example.com/avatar.png"}
    disable_implicit = options.delete(:disable_implicit_sign_up)

    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.generic_oauth(
          config: [
            {
              provider_id: "custom",
              authorization_url: "https://provider.example.com/authorize",
              token_url: "https://provider.example.com/token",
              issuer: "https://provider.example.com",
              client_id: "client-id",
              client_secret: "client-secret",
              scopes: ["profile", "email"],
              disable_implicit_sign_up: disable_implicit,
              get_token: ->(code:, **_data) {
                raise "unexpected code" unless code == "oauth-code"

                {
                  accessToken: "access-token",
                  refreshToken: "refresh-token",
                  idToken: "id-token",
                  scopes: ["openid", "email"]
                }
              },
              get_user_info: ->(_tokens) { user_info }
            }
          ]
        )
      ]
    )
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "OAuth User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
