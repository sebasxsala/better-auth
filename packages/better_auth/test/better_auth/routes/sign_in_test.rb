# frozen_string_literal: true

require "json"
require "stringio"
require_relative "../../test_helper"

class BetterAuthRoutesSignInTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_sign_in_email_returns_token_user_and_cookie
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    auth.api.sign_up_email(body: {email: "ada@example.com", password: "password123", name: "Ada"})

    status, headers, body = auth.api.sign_in_email(
      body: {email: "ADA@example.com", password: "password123"},
      headers: {"x-forwarded-for" => "127.0.0.1", "user-agent" => "Minitest"},
      as_response: true
    )
    data = JSON.parse(body.join)

    assert_equal 200, status
    assert_equal false, data.fetch("redirect")
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("token"))
    assert_equal "ada@example.com", data.fetch("user").fetch("email")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="

    session = auth.context.internal_adapter.find_session(data.fetch("token"))
    assert_equal "127.0.0.1", session[:session]["ipAddress"]
    assert_equal "Minitest", session[:session]["userAgent"]
  end

  def test_sign_in_email_rejects_invalid_credentials
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    auth.api.sign_up_email(body: {email: "bad-password@example.com", password: "password123", name: "Bad Password"})

    wrong_password = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_email(body: {email: "bad-password@example.com", password: "wrong-password"})
    end
    assert_equal 401, wrong_password.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_EMAIL_OR_PASSWORD"], wrong_password.message

    missing_user = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_email(body: {email: "missing@example.com", password: "password123"})
    end
    assert_equal 401, missing_user.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_EMAIL_OR_PASSWORD"], missing_user.message
  end

  def test_sign_in_email_requires_verified_email_when_configured
    sent = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      email_and_password: {enabled: true, require_email_verification: true},
      email_verification: {
        send_on_sign_up: false,
        send_on_sign_in: true,
        send_verification_email: ->(data, _request = nil) { sent << data }
      }
    )
    auth.api.sign_up_email(body: {email: "verify-sign-in@example.com", password: "password123", name: "Verify"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_email(body: {email: "verify-sign-in@example.com", password: "password123", callbackURL: "/dashboard"})
    end

    assert_equal 403, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["EMAIL_NOT_VERIFIED"], error.message
    assert_equal 1, sent.length
    assert_includes sent.first[:url], "callbackURL=%2Fdashboard"
  end

  def test_sign_in_email_does_not_send_verification_when_send_on_sign_in_is_false
    sent = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      email_and_password: {enabled: true, require_email_verification: true},
      email_verification: {
        send_on_sign_up: false,
        send_on_sign_in: false,
        send_verification_email: ->(data, _request = nil) { sent << data }
      }
    )
    auth.api.sign_up_email(body: {email: "no-sign-in-send@example.com", password: "password123", name: "No Send"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_email(body: {email: "no-sign-in-send@example.com", password: "password123"})
    end

    assert_equal 403, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["EMAIL_NOT_VERIFIED"], error.message
    assert_empty sent
  end

  def test_sign_in_email_accepts_form_urlencoded_rack_requests
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    auth.api.sign_up_email(body: {email: "form-sign-in@example.com", password: "password123", name: "Form"})
    form = "email=form-sign-in%40example.com&password=password123"

    status, headers, body = auth.call(
      rack_env(
        "POST",
        "/api/auth/sign-in/email",
        body: form,
        content_type: "application/x-www-form-urlencoded"
      )
    )
    data = JSON.parse(body.join)

    assert_equal 200, status
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("token"))
    assert_equal "form-sign-in@example.com", data.fetch("user").fetch("email")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
  end

  def test_sign_in_email_blocks_cross_site_navigation
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    auth.api.sign_up_email(body: {email: "csrf-sign-in@example.com", password: "password123", name: "CSRF"})

    status, _headers, body = auth.call(
      rack_env(
        "POST",
        "/api/auth/sign-in/email",
        body: JSON.generate(email: "csrf-sign-in@example.com", password: "password123"),
        extra_headers: {
          "HTTP_SEC_FETCH_SITE" => "cross-site",
          "HTTP_SEC_FETCH_MODE" => "navigate",
          "HTTP_SEC_FETCH_DEST" => "document",
          "HTTP_ORIGIN" => "https://evil.example"
        }
      )
    )
    data = JSON.parse(body.join)

    assert_equal 403, status
    assert_equal BetterAuth::BASE_ERROR_CODES["CROSS_SITE_NAVIGATION_LOGIN_BLOCKED"], data.fetch("message")
  end

  private

  def rack_env(method, path, body:, content_type: "application/json", extra_headers: {})
    base = {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(body),
      "CONTENT_TYPE" => content_type,
      "CONTENT_LENGTH" => body.bytesize.to_s,
      "HTTP_ORIGIN" => "http://localhost:3000"
    }
    base.merge(extra_headers)
  end
end
