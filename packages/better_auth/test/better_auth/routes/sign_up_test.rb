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

  def test_sign_up_email_allows_empty_name_and_captures_session_headers
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    result = auth.api.sign_up_email(
      body: {email: "headers@example.com", password: "password123", name: ""},
      headers: {"x-forwarded-for" => "127.0.0.1", "user-agent" => "SignUpTest"}
    )
    session = auth.context.internal_adapter.find_session(result[:token])

    assert_equal "", result[:user]["name"]
    assert_equal "127.0.0.1", session[:session]["ipAddress"]
    assert_equal "SignUpTest", session[:session]["userAgent"]
  end

  def test_sign_up_session_uses_advanced_ip_address_headers
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      advanced: {
        ip_address: {
          ip_address_headers: ["x-client-ip", "x-forwarded-for"]
        }
      }
    )

    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "ip-header@example.com", password: "password123", name: "IP Header"},
      headers: {"x-client-ip" => "203.0.113.10", "x-forwarded-for" => "198.51.100.20", "user-agent" => "SignUpTest"},
      as_response: true
    )
    session = auth.api.get_session(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))})

    assert_equal "203.0.113.10", session[:session]["ipAddress"]
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

  def test_sign_up_email_accepts_form_urlencoded_rack_requests
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    form = "email=form-sign-up%40example.com&password=password123&name=Form+User"

    status, _headers, body = auth.call(
      rack_env(
        "POST",
        "/api/auth/sign-up/email",
        body: form,
        content_type: "application/x-www-form-urlencoded"
      )
    )
    data = JSON.parse(body.join)

    assert_equal 200, status
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("token"))
    assert_equal "form-sign-up@example.com", data.fetch("user").fetch("email")
  end

  def test_sign_up_email_blocks_cross_site_navigation
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    status, _headers, body = auth.call(
      rack_env(
        "POST",
        "/api/auth/sign-up/email",
        body: JSON.generate(email: "csrf@example.com", password: "password123", name: "CSRF"),
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

  def test_sign_up_email_does_not_send_verification_when_send_on_sign_up_is_false
    sent = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      email_and_password: {enabled: true, require_email_verification: true},
      email_verification: {
        send_on_sign_up: false,
        send_verification_email: ->(data, _request = nil) { sent << data }
      }
    )

    result = auth.api.sign_up_email(body: {
      email: "no-send@example.com",
      password: "password123",
      name: "No Send"
    })

    assert_nil result[:token]
    assert_empty sent
  end

  private

  def rack_env(method, path, body: "", content_type: "application/json", extra_headers: {})
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

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end
