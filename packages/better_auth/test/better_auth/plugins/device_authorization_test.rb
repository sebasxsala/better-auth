# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPluginsDeviceAuthorizationTest < Minitest::Test
  SECRET = "phase-eleven-secret-with-enough-entropy-123"

  def test_device_code_polling_approval_and_token_exchange
    auth = build_auth

    issued = auth.api.device_code(body: {client_id: "cli", scope: "openid profile"})
    assert_equal "device-code-123", issued[:device_code]
    assert_equal "ABCD-EFGH", issued[:user_code]
    assert_equal "http://localhost:3000/api/auth/device", issued[:verification_uri]
    assert_equal "http://localhost:3000/api/auth/device?user_code=ABCD-EFGH", issued[:verification_uri_complete]

    pending = assert_raises(BetterAuth::APIError) do
      auth.api.device_token(body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: issued[:device_code], client_id: "cli"})
    end
    assert_equal "authorization_pending", pending.message

    slow_down = assert_raises(BetterAuth::APIError) do
      auth.api.device_token(body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: issued[:device_code], client_id: "cli"})
    end
    assert_equal "slow_down", slow_down.message

    verified = auth.api.device_verify(query: {user_code: "ABCDEFGH"})
    assert_equal "pending", verified[:status]

    cookie = sign_up_cookie(auth)
    approved = auth.api.device_approve(headers: {"cookie" => cookie}, body: {user_code: "ABCD-EFGH"})
    assert_equal({status: true}, approved)

    token = auth.api.device_token(body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: issued[:device_code], client_id: "cli"})
    assert_equal "Bearer", token[:token_type]
    assert token[:access_token]
    assert_equal "openid profile", token[:scope]

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.device_token(body: {grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: issued[:device_code], client_id: "cli"})
    end
    assert_equal "invalid_grant", invalid.message
  end

  def test_client_validation_and_custom_verification_uri
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.device_authorization(
          verification_uri: "/activate",
          validate_client: ->(client_id) { client_id == "valid-client" }
        )
      ]
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.device_code(body: {client_id: "bad-client"})
    end
    assert_equal "invalid_client", error.message

    issued = auth.api.device_code(body: {client_id: "valid-client"})
    assert_equal "http://localhost:3000/api/auth/activate", issued[:verification_uri]
  end

  private

  def build_auth
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.device_authorization(
          interval: "5s",
          generate_device_code: -> { "device-code-123" },
          generate_user_code: -> { "ABCD-EFGH" }
        )
      ]
    )
  end

  def sign_up_cookie(auth)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "device@example.com", password: "password123", name: "Device User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
