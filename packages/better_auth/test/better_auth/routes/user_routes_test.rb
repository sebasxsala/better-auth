# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthRoutesUserTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_update_user_updates_profile_and_rejects_email
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "update@example.com", password: "password123")

    assert_equal({status: true}, auth.api.update_user(headers: {"cookie" => cookie}, body: {name: "Updated", image: nil}))
    assert_equal "Updated", auth.api.get_session(headers: {"cookie" => cookie})[:user]["name"]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.update_user(headers: {"cookie" => cookie}, body: {email: "other@example.com"})
    end

    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["EMAIL_CAN_NOT_BE_UPDATED"], error.message
  end

  def test_change_password_updates_password_and_can_revoke_other_sessions
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "change-password@example.com", password: "password123")
    second_cookie = sign_in_cookie(auth, email: "change-password@example.com", password: "password123")

    result = auth.api.change_password(
      headers: {"cookie" => second_cookie},
      body: {currentPassword: "password123", newPassword: "new-password", revokeOtherSessions: true}
    )

    assert_match(/\A[0-9a-f]{32}\z/, result[:token])
    assert_nil auth.api.get_session(headers: {"cookie" => first_cookie})
    assert auth.api.sign_in_email(body: {email: "change-password@example.com", password: "new-password"})[:token]
  end

  def test_change_password_uses_configured_custom_password_callbacks
    auth = build_auth(
      email_and_password: {
        password: {
          hash: ->(password) { "custom:#{password.reverse}" },
          verify: ->(password, digest) { digest == "custom:#{password.reverse}" }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "custom-change@example.com", password: "password123")

    auth.api.change_password(
      headers: {"cookie" => cookie},
      body: {currentPassword: "password123", newPassword: "new-password"}
    )

    account = auth.context.adapter.find_one(model: "account", where: [{field: "providerId", value: "credential"}])
    assert_equal "custom:drowssap-wen", account["password"]
    assert auth.api.sign_in_email(body: {email: "custom-change@example.com", password: "new-password"})[:token]
  end

  def test_set_password_creates_credential_account_for_session_user_without_password
    auth = build_auth
    user = auth.context.internal_adapter.create_user(email: "set-password@example.com", name: "Set", emailVerified: true)
    cookie = session_cookie(auth, user)

    assert_equal({status: true}, auth.api.set_password(headers: {"cookie" => cookie}, body: {newPassword: "password123"}))
    assert auth.api.sign_in_email(body: {email: "set-password@example.com", password: "password123"})[:token]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.set_password(headers: {"cookie" => cookie}, body: {newPassword: "another-password"})
    end
    assert_equal 400, error.status_code
  end

  def test_change_email_updates_unverified_user_when_enabled
    auth = build_auth(user: {change_email: {enabled: true, update_email_without_verification: true}})
    cookie = sign_up_cookie(auth, email: "old-email@example.com", password: "password123")

    assert_equal({status: true}, auth.api.change_email(headers: {"cookie" => cookie}, body: {newEmail: "new-email@example.com"}))
    assert_equal "new-email@example.com", auth.context.internal_adapter.find_user_by_email("new-email@example.com")[:user]["email"]
  end

  def test_delete_user_deletes_current_user_sessions_and_calls_hooks
    calls = []
    auth = build_auth(
      user: {
        delete_user: {
          enabled: true,
          before_delete: ->(user, _request = nil) { calls << "before:#{user["email"]}" },
          after_delete: ->(user, _request = nil) { calls << "after:#{user["email"]}" }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "delete@example.com", password: "password123")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    result = auth.api.delete_user(headers: {"cookie" => cookie}, body: {password: "password123"})

    assert_equal({success: true, message: "User deleted"}, result)
    assert_equal ["before:delete@example.com", "after:delete@example.com"], calls
    assert_nil auth.context.internal_adapter.find_user_by_id(user_id)
    assert_nil auth.api.get_session(headers: {"cookie" => cookie})
  end

  private

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options).merge(email_and_password: email_and_password))
  end

  def sign_up_cookie(auth, email:, password:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: password, name: "User Routes"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def sign_in_cookie(auth, email:, password:)
    _status, headers, _body = auth.api.sign_in_email(
      body: {email: email, password: password},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def session_cookie(auth, user)
    session = auth.context.internal_adapter.create_session(user["id"])
    token = session["token"]
    name = auth.context.auth_cookies[:session_token].name
    signature = BetterAuth::Crypto.hmac_signature(token, SECRET, encoding: :base64url)
    "#{name}=#{token}.#{signature}"
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end
