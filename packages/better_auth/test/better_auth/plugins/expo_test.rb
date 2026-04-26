# frozen_string_literal: true

require "json"
require "rack/mock"
require_relative "../../test_helper"

class BetterAuthPluginsExpoTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_authorization_proxy_sets_signed_state_cookie_and_redirects
    auth = build_auth
    authorization_url = "https://provider.example.com/auth?state=oauth-state"
    status, headers, _body = auth.api.expo_authorization_proxy(
      query: {authorizationURL: authorization_url},
      as_response: true
    )

    assert_equal 302, status
    assert_equal authorization_url, headers.fetch("location")
    assert_includes headers.fetch("set-cookie"), "better-auth.state="

    status, headers, _body = auth.api.expo_authorization_proxy(
      query: {authorizationURL: authorization_url, oauthState: "cookie-state"},
      as_response: true
    )

    assert_equal 302, status
    assert_includes headers.fetch("set-cookie"), "better-auth.oauth_state=cookie-state"
  end

  def test_expo_origin_header_is_used_when_origin_is_missing
    auth = build_auth
    app = auth.handler
    env = Rack::MockRequest.env_for(
      "http://localhost:3000/api/auth/sign-up/email",
      :method => "POST",
      "CONTENT_TYPE" => "application/json",
      "HTTP_EXPO_ORIGIN" => "http://localhost:3000",
      :input => JSON.generate({email: "expo@example.com", password: "password123", name: "Expo"})
    )

    status, = app.call(env)

    assert_equal 200, status
  end

  def test_deep_link_redirect_receives_cookie_query_param_for_trusted_origin
    auth = build_auth(trusted_origins: ["myapp://"])

    status, headers, _body = auth.api.verify_email(
      query: {token: "missing", callbackURL: "myapp://verified"},
      as_response: true
    )

    assert_equal 302, status
    location = headers.fetch("location")
    assert_match(/\Amyapp:\/\/verified/, location)
    refute_includes location, "cookie="

    ctx = BetterAuth::Endpoint::Context.new(
      path: "/verify-email",
      method: "GET",
      query: {},
      body: {},
      params: {},
      headers: {},
      context: auth.context
    )
    ctx.set_header("location", "myapp://verified")
    ctx.set_header("set-cookie", "better-auth.session_token=abc; Path=/; HttpOnly")
    hook = auth.context.options.plugins.first.hooks.fetch(:after).first
    hook.fetch(:handler).call(ctx)

    assert_includes ctx.response_headers.fetch("location"), "cookie=better-auth.session_token%3Dabc"
  end

  def test_disable_origin_override_preserves_core_missing_origin_behavior
    auth = build_auth(disable_origin_override: true)
    app = auth.handler
    env = Rack::MockRequest.env_for(
      "http://localhost:3000/api/auth/sign-up/email",
      :method => "POST",
      "CONTENT_TYPE" => "application/json",
      "HTTP_EXPO_ORIGIN" => "http://localhost:3000",
      :input => JSON.generate({email: "blocked-expo@example.com", password: "password123", name: "Expo"})
    )

    status, = app.call(env)

    assert_equal 200, status
  end

  private

  def build_auth(plugin_options = {})
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      trusted_origins: plugin_options.delete(:trusted_origins),
      plugins: [BetterAuth::Plugins.expo(plugin_options)]
    )
  end
end
