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

  def test_bearer_accepts_unsigned_token_when_signature_is_not_required
    auth = build_auth(plugins: [BetterAuth::Plugins.bearer])
    result = auth.api.sign_up_email(body: {email: "raw-bearer@example.com", password: "password123", name: "Bearer"})

    session = auth.api.get_session(headers: {"authorization" => "Bearer #{result[:token]}"})

    assert_equal "raw-bearer@example.com", session[:user]["email"]
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end
end
