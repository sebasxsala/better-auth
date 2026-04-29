# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthRoutesEmailVerificationTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_send_verification_email_sends_for_unverified_user_without_leaking_missing_users
    sent = []
    auth = build_auth(email_verification: {send_verification_email: ->(data, _request = nil) { sent << data }})
    auth.api.sign_up_email(body: {email: "verify-me@example.com", password: "password123", name: "Verify"})

    assert_equal({status: true}, auth.api.send_verification_email(body: {email: "verify-me@example.com", callbackURL: "/dashboard"}))
    assert_equal({status: true}, auth.api.send_verification_email(body: {email: "missing@example.com"}))

    assert_equal 1, sent.length
    assert_equal "verify-me@example.com", sent.first[:user]["email"]
    assert_includes sent.first[:url], "/verify-email?token="
    assert_includes sent.first[:url], "callbackURL=%2Fdashboard"
  end

  def test_send_verification_email_rejects_mismatched_authenticated_user
    sent = []
    auth = build_auth(email_verification: {send_verification_email: ->(data, _request = nil) { sent << data }})
    cookie = sign_up_cookie(auth, email: "session-email@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.send_verification_email(headers: {"cookie" => cookie}, body: {email: "other@example.com"})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["EMAIL_MISMATCH"], error.message
    assert_empty sent
  end

  def test_verify_email_marks_user_verified_and_can_set_session_cookie
    verified = []
    auth = build_auth(
      email_verification: {
        auto_sign_in_after_verification: true,
        before_email_verification: ->(user, _request = nil) { verified << "before:#{user["email"]}" },
        on_email_verification: ->(user, _request = nil) { verified << "on:#{user["email"]}" },
        after_email_verification: ->(user, _request = nil) { verified << "after:#{user["email"]}" }
      }
    )
    auth.api.sign_up_email(body: {email: "verified@example.com", password: "password123", name: "Verified"})
    token = BetterAuth::Crypto.sign_jwt({"email" => "verified@example.com"}, SECRET, expires_in: 3600)

    status, headers, body = auth.api.verify_email(query: {token: token}, as_response: true)

    assert_equal 200, status
    assert_equal({"status" => true, "user" => nil}, JSON.parse(body.join))
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_equal ["before:verified@example.com", "on:verified@example.com", "after:verified@example.com"], verified
    user = auth.context.internal_adapter.find_user_by_email("verified@example.com")[:user]
    assert_equal true, user["emailVerified"]
  end

  def test_verify_email_rejects_untrusted_callback_url
    auth = build_auth
    auth.api.sign_up_email(body: {email: "unsafe-callback@example.com", password: "password123", name: "Unsafe"})
    token = BetterAuth::Crypto.sign_jwt({"email" => "unsafe-callback@example.com"}, SECRET, expires_in: 3600)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_email(query: {token: token, callbackURL: "https://evil.example/callback"})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["INVALID_CALLBACK_URL"], error.message
  end

  def test_change_email_verification_updates_email_as_unverified_and_sends_new_verification
    sent = []
    auth = build_auth(
      user: {change_email: {enabled: true}},
      email_verification: {send_verification_email: ->(data, _request = nil) { sent << data }}
    )
    cookie = sign_up_cookie(auth, email: "old-verified@example.com")
    auth.context.internal_adapter.update_user_by_email("old-verified@example.com", emailVerified: true)

    assert_equal({status: true}, auth.api.change_email(headers: {"cookie" => cookie}, body: {newEmail: "new-verified@example.com"}))
    first_token = sent.first.fetch(:token)

    auth.api.verify_email(query: {token: first_token})

    old_user = auth.context.internal_adapter.find_user_by_email("old-verified@example.com")
    new_user = auth.context.internal_adapter.find_user_by_email("new-verified@example.com")[:user]
    assert_nil old_user
    assert_equal false, new_user["emailVerified"]
    assert_equal 2, sent.length
    assert_equal "new-verified@example.com", sent.last.fetch(:user).fetch("email")
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Email User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
