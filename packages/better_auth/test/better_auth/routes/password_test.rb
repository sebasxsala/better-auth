# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthRoutesPasswordTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_request_password_reset_sends_generic_response_and_reset_password_updates_credential
    sent = []
    reset = []
    auth = build_auth(
      email_and_password: {
        send_reset_password: ->(data, _request = nil) { sent << data },
        on_password_reset: ->(data, _request = nil) { reset << data[:user]["email"] },
        revoke_sessions_on_password_reset: true
      }
    )
    cookie = sign_up_cookie(auth, email: "reset@example.com", password: "old-password")
    old_session = auth.api.get_session(headers: {"cookie" => cookie})[:session]["token"]

    response = auth.api.request_password_reset(body: {email: "reset@example.com", redirectTo: "/reset"})

    assert_equal({status: true, message: "If this email exists in our system, check your email for the reset link"}, response)
    assert_equal 1, sent.length
    assert_equal "reset@example.com", sent.first[:user]["email"]
    assert_match(%r{/reset-password/[^?]+\?callbackURL=%2Freset}, sent.first[:url])

    token = sent.first[:token]
    assert_equal({status: true}, auth.api.reset_password(body: {token: token, newPassword: "new-password"}))

    assert_equal ["reset@example.com"], reset
    assert_nil auth.context.internal_adapter.find_verification_value("reset-password:#{token}")
    assert_nil auth.context.internal_adapter.find_session(old_session)
    assert auth.api.sign_in_email(body: {email: "reset@example.com", password: "new-password"})[:token]
  end

  def test_request_password_reset_does_not_leak_missing_users
    sent = []
    auth = build_auth(email_and_password: {send_reset_password: ->(data, _request = nil) { sent << data }})

    response = auth.api.request_password_reset(body: {email: "missing@example.com"})

    assert_equal true, response[:status]
    assert_empty sent
  end

  def test_reset_password_callback_redirects_with_token_or_invalid_token_error
    auth = build_auth(email_and_password: {send_reset_password: ->(_data, _request = nil) {}})
    auth.api.sign_up_email(body: {email: "callback-reset@example.com", password: "old-password", name: "Reset"})
    auth.api.request_password_reset(body: {email: "callback-reset@example.com", redirectTo: "/reset"})
    verification = auth.context.adapter.find_many(model: "verification").first
    token = verification["identifier"].delete_prefix("reset-password:")

    status, headers, _body = auth.api.request_password_reset_callback(
      params: {token: token},
      query: {callbackURL: "/reset"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/reset?token=#{token}", headers["location"]

    status, headers, _body = auth.api.request_password_reset_callback(
      params: {token: "bad-token"},
      query: {callbackURL: "/reset"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/reset?error=INVALID_TOKEN", headers["location"]
  end

  def test_verify_password_requires_current_password_for_session_user
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "verify-password@example.com", password: "password123")

    assert_equal({status: true}, auth.api.verify_password(headers: {"cookie" => cookie}, body: {password: "password123"}))

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_password(headers: {"cookie" => cookie}, body: {password: "bad-password"})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_PASSWORD"], error.message
  end

  private

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options).merge(email_and_password: email_and_password))
  end

  def sign_up_cookie(auth, email:, password:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: password, name: "Password User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end
