# frozen_string_literal: true

require "json"
require "rack/mock"
require_relative "../../test_helper"

class BetterAuthPluginsEmailOTPTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"

  def test_sends_and_verifies_email_otp_for_existing_user
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.email_otp(send_verification_otp: ->(data, _ctx = nil) { sent << data })
      ]
    )
    auth.api.sign_up_email(body: {email: "verify@example.com", password: "password123", name: "Verify"})

    assert_equal({success: true}, auth.api.send_verification_otp(body: {email: "verify@example.com", type: "email-verification"}))
    assert_equal "verify@example.com", sent.first[:email]
    assert_equal "email-verification", sent.first[:type]
    assert_match(/\A\d{6}\z/, sent.first[:otp])

    result = auth.api.verify_email_otp(body: {email: "verify@example.com", otp: sent.first[:otp]})

    assert_equal true, result[:status]
    assert_nil result[:token]
    assert_equal true, result[:user]["emailVerified"]
    assert_equal true, auth.context.internal_adapter.find_user_by_email("verify@example.com")[:user]["emailVerified"]
  end

  def test_sign_in_with_email_otp_creates_session_and_can_sign_up_new_users
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.email_otp(send_verification_otp: ->(data, _ctx = nil) { sent << data })
      ]
    )
    auth.api.sign_up_email(body: {email: "signin@example.com", password: "password123", name: "Sign In"})

    auth.api.send_verification_otp(body: {email: "signin@example.com", type: "sign-in"})
    status, headers, body = auth.api.sign_in_email_otp(
      body: {email: "signin@example.com", otp: sent.last[:otp]},
      as_response: true
    )
    data = JSON.parse(body.join)

    assert_equal 200, status
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("token"))
    assert_equal "signin@example.com", data.fetch("user").fetch("email")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="

    auth.api.send_verification_otp(body: {email: "new-otp@example.com", type: "sign-in"})
    result = auth.api.sign_in_email_otp(body: {email: "new-otp@example.com", otp: sent.last[:otp]})

    assert_match(/\A[0-9a-f]{32}\z/, result[:token])
    assert_equal "new-otp@example.com", result[:user]["email"]
    assert_equal true, result[:user]["emailVerified"]
  end

  def test_sign_in_with_email_otp_normalizes_email_case
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.email_otp(send_verification_otp: ->(data, _ctx = nil) { sent << data })
      ]
    )

    auth.api.send_verification_otp(body: {email: "CASE-OTP@Example.COM", type: "sign-in"})
    result = auth.api.sign_in_email_otp(body: {email: "case-otp@example.com", otp: sent.last[:otp]})

    assert_equal "case-otp@example.com", result[:user]["email"]
    assert_equal true, result[:user]["emailVerified"]
  end

  def test_send_verification_otp_prevents_enumeration_when_sign_up_is_disabled
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.email_otp(
          disable_sign_up: true,
          send_verification_otp: ->(data, _ctx = nil) { sent << data }
        )
      ]
    )
    auth.api.sign_up_email(body: {email: "existing-otp@example.com", password: "password123", name: "Existing"})

    missing = auth.api.send_verification_otp(body: {email: "missing-otp@example.com", type: "sign-in"})
    existing = auth.api.send_verification_otp(body: {email: "existing-otp@example.com", type: "sign-in"})

    assert_equal({success: true}, missing)
    assert_equal({success: true}, existing)
    assert_equal ["existing-otp@example.com"], sent.map { |entry| entry[:email] }
  end

  def test_email_otp_verifies_last_issued_otp
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.email_otp(send_verification_otp: ->(data, _ctx = nil) { sent << data })
      ]
    )
    auth.api.sign_up_email(body: {email: "latest-otp@example.com", password: "password123", name: "Latest"})

    3.times { auth.api.send_verification_otp(body: {email: "latest-otp@example.com", type: "email-verification"}) }
    result = auth.api.verify_email_otp(body: {email: "latest-otp@example.com", otp: sent.last[:otp]})

    assert_equal true, result[:status]
    assert_equal true, result[:user]["emailVerified"]
  end

  def test_check_otp_tracks_attempts_and_rejects_too_many_failures
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.email_otp(
          allowed_attempts: 2,
          send_verification_otp: ->(data, _ctx = nil) { sent << data }
        )
      ]
    )
    auth.api.sign_up_email(body: {email: "attempts@example.com", password: "password123", name: "Attempts"})
    auth.api.send_verification_otp(body: {email: "attempts@example.com", type: "email-verification"})

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.check_verification_otp(body: {email: "attempts@example.com", type: "email-verification", otp: "000000"})
    end
    assert_equal 400, invalid.status_code
    assert_equal BetterAuth::Plugins::EMAIL_OTP_ERROR_CODES["INVALID_OTP"], invalid.message

    second = assert_raises(BetterAuth::APIError) do
      auth.api.check_verification_otp(body: {email: "attempts@example.com", type: "email-verification", otp: "111111"})
    end
    assert_equal 400, second.status_code

    too_many = assert_raises(BetterAuth::APIError) do
      auth.api.check_verification_otp(body: {email: "attempts@example.com", type: "email-verification", otp: sent.first[:otp]})
    end
    assert_equal 403, too_many.status_code
    assert_equal BetterAuth::Plugins::EMAIL_OTP_ERROR_CODES["TOO_MANY_ATTEMPTS"], too_many.message
  end

  def test_expired_email_otp_is_rejected_and_consumed
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.email_otp(
          expires_in: -1,
          send_verification_otp: ->(data, _ctx = nil) { sent << data }
        )
      ]
    )
    auth.api.sign_up_email(body: {email: "expired-otp@example.com", password: "password123", name: "Expired"})
    auth.api.send_verification_otp(body: {email: "expired-otp@example.com", type: "email-verification"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_email_otp(body: {email: "expired-otp@example.com", otp: sent.first[:otp]})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::Plugins::EMAIL_OTP_ERROR_CODES["OTP_EXPIRED"], error.message
    assert_nil auth.context.internal_adapter.find_verification_value("email-verification-otp-expired-otp@example.com")
  end

  def test_server_otp_helpers_support_custom_length_and_secure_storage_modes
    hashed = build_auth(
      plugins: [
        BetterAuth::Plugins.email_otp(
          otp_length: 8,
          store_otp: "hashed",
          generate_otp: ->(_data, _ctx = nil) { "12345678" },
          send_verification_otp: ->(_data, _ctx = nil) {}
        )
      ]
    )

    otp = hashed.api.create_verification_otp(body: {email: "hash@example.com", type: "sign-in"})
    stored = hashed.context.internal_adapter.find_verification_value("sign-in-otp-hash@example.com")

    assert_equal "12345678", otp
    refute_equal "12345678", stored["value"].split(":").first
    assert_equal 8, otp.length

    error = assert_raises(BetterAuth::APIError) do
      hashed.api.get_verification_otp(query: {email: "hash@example.com", type: "sign-in"})
    end
    assert_equal 400, error.status_code
    assert_equal "OTP is hashed, cannot return the plain text OTP", error.message

    encrypted = build_auth(
      plugins: [
        BetterAuth::Plugins.email_otp(
          store_otp: "encrypted",
          generate_otp: ->(_data, _ctx = nil) { "654321" },
          send_verification_otp: ->(_data, _ctx = nil) {}
        )
      ]
    )
    encrypted.api.create_verification_otp(body: {email: "encrypted@example.com", type: "sign-in"})

    assert_equal({otp: "654321"}, encrypted.api.get_verification_otp(query: {email: "encrypted@example.com", type: "sign-in"}))
    assert_match(/\A[0-9a-f]{32}\z/, encrypted.api.sign_in_email_otp(body: {email: "encrypted@example.com", otp: "654321"})[:token])
  end

  def test_server_otp_helpers_support_custom_encryptor_and_hasher_storage
    encrypted = build_auth(
      plugins: [
        BetterAuth::Plugins.email_otp(
          store_otp: {
            encrypt: ->(otp) { "#{otp}:encrypted" },
            decrypt: ->(stored) { stored.delete_suffix(":encrypted") }
          },
          generate_otp: ->(_data, _ctx = nil) { "246810" },
          send_verification_otp: ->(_data, _ctx = nil) {}
        )
      ]
    )
    encrypted.api.create_verification_otp(body: {email: "custom-encrypted@example.com", type: "sign-in"})

    assert_equal({otp: "246810"}, encrypted.api.get_verification_otp(query: {email: "custom-encrypted@example.com", type: "sign-in"}))
    assert_match(/\A[0-9a-f]{32}\z/, encrypted.api.sign_in_email_otp(body: {email: "custom-encrypted@example.com", otp: "246810"})[:token])

    hashed = build_auth(
      plugins: [
        BetterAuth::Plugins.email_otp(
          store_otp: {hash: ->(otp) { "#{otp}:hashed" }},
          generate_otp: ->(_data, _ctx = nil) { "135791" },
          send_verification_otp: ->(_data, _ctx = nil) {}
        )
      ]
    )
    hashed.api.create_verification_otp(body: {email: "custom-hashed@example.com", type: "sign-in"})

    error = assert_raises(BetterAuth::APIError) do
      hashed.api.get_verification_otp(query: {email: "custom-hashed@example.com", type: "sign-in"})
    end
    assert_equal 400, error.status_code
    assert_match(/\A[0-9a-f]{32}\z/, hashed.api.sign_in_email_otp(body: {email: "custom-hashed@example.com", otp: "135791"})[:token])
  end

  def test_password_reset_with_email_otp_updates_password_and_revokes_sessions
    sent = []
    reset_calls = []
    auth = build_auth(
      email_and_password: {on_password_reset: ->(data, _request = nil) { reset_calls << data }, revoke_sessions_on_password_reset: true},
      plugins: [
        BetterAuth::Plugins.email_otp(send_verification_otp: ->(data, _ctx = nil) { sent << data })
      ]
    )
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "reset-otp@example.com", password: "password123", name: "Reset"},
      as_response: true
    )
    cookie = cookie_header(headers.fetch("set-cookie"))

    assert_equal({success: true}, auth.api.request_password_reset_email_otp(body: {email: "reset-otp@example.com"}))
    assert_equal "forget-password", sent.first[:type]
    assert_equal({success: true}, auth.api.reset_password_email_otp(body: {email: "reset-otp@example.com", otp: sent.first[:otp], password: "newpassword123"}))

    assert_equal 1, reset_calls.length
    assert_nil auth.api.get_session(headers: {"cookie" => cookie})
    assert_match(/\A[0-9a-f]{32}\z/, auth.api.sign_in_email(body: {email: "reset-otp@example.com", password: "newpassword123"})[:token])
  end

  def test_send_verification_on_sign_up_uses_configured_delivery_callback
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.email_otp(
          send_verification_on_sign_up: true,
          send_verification_otp: ->(data, _ctx = nil) { sent << data }
        )
      ]
    )

    auth.api.sign_up_email(body: {email: "signup-otp@example.com", password: "password123", name: "Signup"})

    assert_equal "signup-otp@example.com", sent.first[:email]
    assert_equal "email-verification", sent.first[:type]
    assert_match(/\A\d{6}\z/, sent.first[:otp])
    assert auth.context.internal_adapter.find_verification_value("email-verification-otp-signup-otp@example.com")
  end

  def test_override_default_email_verification_sends_once_and_calls_after_hook
    sent = []
    after_calls = []
    auth = build_auth(
      email_verification: {
        send_on_sign_up: true,
        after_email_verification: ->(user, _request = nil) { after_calls << user }
      },
      plugins: [
        BetterAuth::Plugins.email_otp(
          override_default_email_verification: true,
          send_verification_on_sign_up: true,
          send_verification_otp: ->(data, _ctx = nil) { sent << data }
        )
      ]
    )

    auth.api.sign_up_email(body: {email: "override-otp@example.com", password: "password123", name: "Override"})
    result = auth.api.verify_email_otp(body: {email: "override-otp@example.com", otp: sent.first[:otp]})

    assert_equal 1, sent.length
    assert_equal true, result[:user]["emailVerified"]
    assert_equal 1, after_calls.length
    assert_equal "override-otp@example.com", after_calls.first["email"]
    assert_equal true, after_calls.first["emailVerified"]
  end

  def test_email_otp_routes_use_plugin_rate_limits
    auth = build_auth(
      rate_limit: {enabled: true},
      plugins: [
        BetterAuth::Plugins.email_otp(send_verification_otp: ->(_data, _ctx = nil) {})
      ]
    )
    app = auth.handler

    statuses = 4.times.map do
      status, _headers, _body = app.call(rack_json_env(
        "/api/auth/email-otp/send-verification-otp",
        {email: "rate-limited@example.com", type: "sign-in"}
      ))
      status
    end

    assert_equal [200, 200, 200, 429], statuses
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end

  def rack_json_env(path, body)
    Rack::MockRequest.env_for(
      "http://localhost:3000#{path}",
      :method => "POST",
      "CONTENT_TYPE" => "application/json",
      "REMOTE_ADDR" => "127.0.0.1",
      :input => JSON.generate(body)
    )
  end
end
