# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPluginsBearerTest < Minitest::Test
  SECRET = "phase-seven-secret-with-enough-entropy-123"

  def test_bearer_exposes_auth_token_and_accepts_authorization_header
    auth = build_auth(plugins: [BetterAuth::Plugins.bearer])

    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "bearer@example.com", password: "password123", name: "Bearer"},
      as_response: true
    )
    token = headers.fetch("set-auth-token")

    session = auth.api.get_session(headers: {"authorization" => "Bearer #{token}"})

    assert_equal "bearer@example.com", session[:user]["email"]
  end

  def test_bearer_authorizes_list_sessions
    auth = build_auth(plugins: [BetterAuth::Plugins.bearer])
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "bearer-list@example.com", password: "password123", name: "Bearer"},
      as_response: true
    )
    token = headers.fetch("set-auth-token")

    sessions = auth.api.list_sessions(headers: {"authorization" => "Bearer #{token}"})

    assert_equal 1, sessions.length
    assert_equal auth.api.get_session(headers: {"authorization" => "Bearer #{token}"})[:session]["userId"], sessions.first["userId"]
  end

  def test_bearer_works_with_direct_api_headers
    auth = build_auth(plugins: [BetterAuth::Plugins.bearer])
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "bearer-direct@example.com", password: "password123", name: "Bearer"},
      as_response: true
    )
    token = headers.fetch("set-auth-token")

    session = auth.api.get_session(headers: {"Authorization" => "Bearer #{token}"})

    assert_equal "bearer-direct@example.com", session[:user]["email"]
  end

  def test_bearer_accepts_unsigned_token_when_signature_is_not_required
    auth = build_auth(plugins: [BetterAuth::Plugins.bearer])
    result = auth.api.sign_up_email(body: {email: "raw-bearer@example.com", password: "password123", name: "Bearer"})

    session = auth.api.get_session(headers: {"authorization" => "Bearer #{result[:token]}"})

    assert_equal "raw-bearer@example.com", session[:user]["email"]
  end

  def test_bearer_rejects_unsigned_token_when_signature_is_required
    auth = build_auth(plugins: [BetterAuth::Plugins.bearer(require_signature: true)])
    result = auth.api.sign_up_email(body: {email: "signed-only@example.com", password: "password123", name: "Bearer"})

    session = auth.api.get_session(headers: {"authorization" => "Bearer #{result[:token]}"})

    assert_nil session
  end

  def test_bearer_falls_back_to_valid_cookie_when_authorization_header_is_invalid
    auth = build_auth(plugins: [BetterAuth::Plugins.bearer])
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "bearer-cookie@example.com", password: "password123", name: "Bearer"},
      as_response: true
    )
    token = headers.fetch("set-auth-token")

    session = auth.api.get_session(
      headers: {
        "authorization" => "Bearer invalid.token",
        "cookie" => "better-auth.session_token=#{token}"
      }
    )

    assert_equal "bearer-cookie@example.com", session[:user]["email"]
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end
end
