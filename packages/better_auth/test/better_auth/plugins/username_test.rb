# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsUsernameTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"

  def test_username_sign_up_sign_in_update_and_availability
    auth = build_auth(plugins: [BetterAuth::Plugins.username(min_username_length: 4)])

    _status, headers, _body = auth.api.sign_up_email(
      body: {
        email: "new-email@example.com",
        username: "New_User",
        password: "password123",
        name: "New User"
      },
      as_response: true
    )
    cookie = cookie_header(headers.fetch("set-cookie"))
    session = auth.api.get_session(headers: {"cookie" => cookie})

    assert_equal "new_user", session[:user]["username"]
    assert_equal "New_User", session[:user]["displayUsername"]

    sign_in = auth.api.sign_in_username(body: {username: "NEW_USER", password: "password123"})
    assert_match(/\A[0-9a-f]{32}\z/, sign_in[:token])
    assert_equal "new_user", sign_in[:user]["username"]

    auth.api.update_user(headers: {"cookie" => cookie}, body: {username: "priority_user", displayUsername: "Priority Display"})
    updated = auth.api.get_session(headers: {"cookie" => cookie}, query: {disableCookieCache: true})
    assert_equal "priority_user", updated[:user]["username"]
    assert_equal "Priority Display", updated[:user]["displayUsername"]

    unavailable = auth.api.is_username_available(body: {username: "PRIORITY_USER"})
    assert_equal({available: false}, unavailable)
    available = auth.api.is_username_available(body: {username: "fresh_user"})
    assert_equal({available: true}, available)
  end

  def test_username_rejects_duplicates_and_invalid_values
    auth = build_auth(plugins: [BetterAuth::Plugins.username(min_username_length: 4)])
    auth.api.sign_up_email(body: {email: "one@example.com", username: "first_user", password: "password123", name: "One"})

    duplicate = assert_raises(BetterAuth::APIError) do
      auth.api.sign_up_email(body: {email: "two@example.com", username: "FIRST_USER", password: "password123", name: "Two"})
    end
    assert_equal 400, duplicate.status_code
    assert_equal BetterAuth::Plugins::USERNAME_ERROR_CODES["USERNAME_IS_ALREADY_TAKEN"], duplicate.message

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.sign_up_email(body: {email: "bad@example.com", username: "bad user", password: "password123", name: "Bad"})
    end
    assert_equal 400, invalid.status_code
    assert_equal BetterAuth::Plugins::USERNAME_ERROR_CODES["INVALID_USERNAME"], invalid.message

    too_short = assert_raises(BetterAuth::APIError) do
      auth.api.is_username_available(body: {username: "abc"})
    end
    assert_equal 422, too_short.status_code
    assert_equal BetterAuth::Plugins::USERNAME_ERROR_CODES["USERNAME_TOO_SHORT"], too_short.message
  end

  def test_username_custom_normalization_and_validators
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.username(
          min_username_length: 4,
          username_normalization: ->(value) { value.tr("04", "oa").downcase },
          display_username_normalization: ->(value) { value.downcase },
          display_username_validator: ->(value) { value.match?(/\A[a-zA-Z0-9_\-\s]+\z/) }
        )
      ]
    )

    result = auth.api.sign_up_email(
      body: {
        email: "normal@example.com",
        username: "H4XX0R",
        displayUsername: "Fancy Name",
        password: "password123",
        name: "Normal"
      }
    )

    assert_equal "haxxor", result[:user]["username"]
    assert_equal "fancy name", result[:user]["displayUsername"]

    duplicate = assert_raises(BetterAuth::APIError) do
      auth.api.sign_up_email(body: {email: "copy@example.com", username: "haxxor", password: "password123", name: "Copy"})
    end
    assert_equal BetterAuth::Plugins::USERNAME_ERROR_CODES["USERNAME_IS_ALREADY_TAKEN"], duplicate.message

    invalid_display = assert_raises(BetterAuth::APIError) do
      auth.api.sign_up_email(body: {email: "display@example.com", displayUsername: "Invalid!", password: "password123", name: "Display"})
    end
    assert_equal BetterAuth::Plugins::USERNAME_ERROR_CODES["INVALID_DISPLAY_USERNAME"], invalid_display.message
  end

  def test_username_email_verification_does_not_leak_until_password_is_valid
    auth = build_auth(
      email_and_password: {enabled: true, require_email_verification: true},
      email_verification: {send_on_sign_up: false},
      plugins: [BetterAuth::Plugins.username]
    )
    auth.api.sign_up_email(body: {email: "unverified@example.com", username: "unverified_user", password: "password123", name: "Unverified"})

    wrong_password = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_username(body: {username: "unverified_user", password: "wrong-password"})
    end
    assert_equal 401, wrong_password.status_code
    assert_equal BetterAuth::Plugins::USERNAME_ERROR_CODES["INVALID_USERNAME_OR_PASSWORD"], wrong_password.message

    correct_password = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_username(body: {username: "unverified_user", password: "password123"})
    end
    assert_equal 403, correct_password.status_code
    assert_equal BetterAuth::Plugins::USERNAME_ERROR_CODES["EMAIL_NOT_VERIFIED"], correct_password.message
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end
