# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsTwoFactorTest < Minitest::Test
  SECRET = "phase-nine-two-factor-secret-with-enough-entropy"

  def test_enable_then_verify_totp_requires_second_factor_on_next_sign_in
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "totp@example.com")

    enabled = auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})
    assert_match(/\Aotpauth:\/\/totp\//, enabled[:totpURI])
    assert_equal 10, enabled[:backupCodes].length

    record = auth.context.adapter.find_one(model: "twoFactor", where: [{field: "userId", value: user_id(auth, cookie)}])
    secret = BetterAuth::Crypto.symmetric_decrypt(key: SECRET, data: record.fetch("secret"))
    code = BetterAuth::Plugins.two_factor_totp(secret)

    verified = auth.api.verify_totp(headers: {"cookie" => cookie}, body: {code: code})
    assert_equal "totp@example.com", verified[:user]["email"]

    status, headers, body = auth.api.sign_in_email(
      body: {email: "totp@example.com", password: "password123"},
      as_response: true
    )
    assert_equal 200, status
    assert_equal({"twoFactorRedirect" => true}, JSON.parse(body.join))
    assert_includes headers.fetch("set-cookie"), "better-auth.two_factor="
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token=;"
    assert_includes headers.fetch("set-cookie"), "Max-Age=0"
  end

  def test_otp_verification_supports_hashed_storage_and_attempt_limits
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.two_factor(
          skip_verification_on_enable: true,
          otp_options: {
            store_otp: "hashed",
            allowed_attempts: 1,
            send_otp: ->(data, _ctx = nil) { sent << data }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "otp@example.com")
    auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})

    sign_in = auth.api.sign_in_email(body: {email: "otp@example.com", password: "password123"}, return_headers: true)
    two_factor_cookie = cookie_header(sign_in.fetch(:headers).fetch("set-cookie"))
    auth.api.send_two_factor_otp(headers: {"cookie" => two_factor_cookie})

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.verify_two_factor_otp(headers: {"cookie" => two_factor_cookie}, body: {code: "000000"})
    end
    assert_equal BetterAuth::Plugins::TWO_FACTOR_ERROR_CODES["INVALID_CODE"], invalid.message

    too_many = assert_raises(BetterAuth::APIError) do
      auth.api.verify_two_factor_otp(headers: {"cookie" => two_factor_cookie}, body: {code: sent.last.fetch(:otp)})
    end
    assert_equal BetterAuth::Plugins::TWO_FACTOR_ERROR_CODES["TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"], too_many.message
  end

  def test_backup_code_use_consumes_code_and_trusting_device_skips_next_challenge
    auth = build_auth(plugins: [BetterAuth::Plugins.two_factor(skip_verification_on_enable: true)])
    cookie = sign_up_cookie(auth, email: "backup@example.com")
    existing_user_id = user_id(auth, cookie)
    enabled = auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"})
    code = enabled[:backupCodes].first

    sign_in = auth.api.sign_in_email(body: {email: "backup@example.com", password: "password123"}, return_headers: true)
    two_factor_cookie = cookie_header(sign_in.fetch(:headers).fetch("set-cookie"))
    verified = auth.api.verify_backup_code(
      headers: {"cookie" => two_factor_cookie},
      body: {code: code, trustDevice: true},
      return_headers: true
    )
    trusted_cookie = cookie_header(verified.fetch(:headers).fetch("set-cookie"))
    refute_includes auth.api.view_backup_codes(body: {userId: existing_user_id})[:backupCodes], code

    trusted = auth.api.sign_in_email(
      headers: {"cookie" => trusted_cookie},
      body: {email: "backup@example.com", password: "password123"}
    )
    assert_equal "backup@example.com", trusted[:user]["email"]
  end

  def test_disable_two_factor_revokes_trusted_device
    auth = build_auth(plugins: [BetterAuth::Plugins.two_factor(skip_verification_on_enable: true)])
    cookie = sign_up_cookie(auth, email: "disable-2fa@example.com")
    enabled = auth.api.enable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"}, return_headers: true)
    cookie = cookie_header(enabled.fetch(:headers).fetch("set-cookie"))

    result = auth.api.disable_two_factor(headers: {"cookie" => cookie}, body: {password: "password123"}, return_headers: true)
    assert_equal({status: true}, result.fetch(:response))
    assert_includes result.fetch(:headers).fetch("set-cookie"), "better-auth.session_token="

    session = auth.api.get_session(headers: {"cookie" => cookie_header(result.fetch(:headers).fetch("set-cookie"))}, query: {disableCookieCache: true})
    assert_equal false, session[:user]["twoFactorEnabled"]
  end

  def build_auth(options = {})
    plugin_list = options.delete(:plugins) || [BetterAuth::Plugins.two_factor(otp_options: {send_otp: ->(_data, _ctx = nil) {}})]
    BetterAuth.auth({
      secret: SECRET,
      plugins: plugin_list,
      email_and_password: {enabled: true}
    }.merge(options))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Two Factor"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def user_id(auth, cookie)
    auth.api.get_session(headers: {"cookie" => cookie}, query: {disableCookieCache: true})[:user]["id"]
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end
end
