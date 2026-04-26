# frozen_string_literal: true

require "json"
require "stringio"
require_relative "../../test_helper"

class BetterAuthRoutesSignUpTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_sign_up_email_creates_user_account_and_session
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    result = auth.api.sign_up_email(body: {
      email: "Ada@Example.COM",
      password: "password123",
      name: "Ada Lovelace",
      image: "https://example.com/ada.png"
    })

    assert_match(/\A[0-9a-f]{32}\z/, result[:token])
    assert_equal "ada@example.com", result[:user]["email"]
    assert_equal "Ada Lovelace", result[:user]["name"]
    assert_equal false, result[:user]["emailVerified"]

    account = auth.context.adapter.find_one(model: "account", where: [{field: "userId", value: result[:user]["id"]}])
    assert_equal "credential", account["providerId"]
    assert_equal result[:user]["id"], account["accountId"]
    assert BetterAuth::Password.verify(password: "password123", hash: account["password"])
  end

  def test_sign_up_email_sets_session_cookie_for_rack_requests
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    status, headers, body = auth.call(
      rack_env(
        "POST",
        "/api/auth/sign-up/email",
        body: JSON.generate(email: "cookie@example.com", password: "password123", name: "Cookie User")
      )
    )

    data = JSON.parse(body.join)
    assert_equal 200, status
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("token"))
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
  end

  def test_sign_up_email_rejects_invalid_email_and_short_password
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    invalid_email = assert_raises(BetterAuth::APIError) do
      auth.api.sign_up_email(body: {email: "invalid", password: "password123", name: "Bad Email"})
    end
    assert_equal 400, invalid_email.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_EMAIL"], invalid_email.message

    short_password = assert_raises(BetterAuth::APIError) do
      auth.api.sign_up_email(body: {email: "short@example.com", password: "short", name: "Short Password"})
    end
    assert_equal 400, short_password.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["PASSWORD_TOO_SHORT"], short_password.message
  end

  def test_sign_up_email_rejects_duplicate_email
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    auth.api.sign_up_email(body: {email: "duplicate@example.com", password: "password123", name: "First"})
    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_up_email(body: {email: "DUPLICATE@example.com", password: "password123", name: "Second"})
    end

    assert_equal 422, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"], error.message
  end

  def test_sign_up_email_can_be_disabled
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      email_and_password: {enabled: true, disable_sign_up: true}
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_up_email(body: {email: "disabled@example.com", password: "password123", name: "Disabled"})
    end

    assert_equal 400, error.status_code
    assert_equal "Email and password sign up is not enabled", error.message
  end

  def test_sign_up_email_requires_verification_without_auto_session
    sent = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      email_and_password: {enabled: true, require_email_verification: true},
      email_verification: {
        send_verification_email: ->(data, _request = nil) { sent << data }
      }
    )

    result = auth.api.sign_up_email(body: {
      email: "verify@example.com",
      password: "password123",
      name: "Verify Me",
      callbackURL: "/dashboard"
    })

    assert_nil result[:token]
    assert_equal "verify@example.com", result[:user]["email"]
    assert_equal 1, sent.length
    assert_equal "verify@example.com", sent.first[:user]["email"]
    assert_includes sent.first[:url], "/verify-email?token="
    assert_includes sent.first[:url], "callbackURL=%2Fdashboard"
  end

  private

  def rack_env(method, path, body: "")
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(body),
      "CONTENT_TYPE" => "application/json",
      "CONTENT_LENGTH" => body.bytesize.to_s,
      "HTTP_ORIGIN" => "http://localhost:3000"
    }
  end
end
