# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsAnonymousTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"

  def test_anonymous_sign_in_creates_session_and_anonymous_user
    auth = build_auth(plugins: [BetterAuth::Plugins.anonymous])

    status, headers, body = auth.api.sign_in_anonymous(as_response: true)
    data = JSON.parse(body.join)
    cookie = cookie_header(headers.fetch("set-cookie"))
    session = auth.api.get_session(headers: {"cookie" => cookie})

    assert_equal 200, status
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("token"))
    assert_equal true, data.fetch("user").fetch("isAnonymous")
    assert_equal "Anonymous", data.fetch("user").fetch("name")
    assert_equal true, session[:user]["isAnonymous"]
  end

  def test_anonymous_sign_in_supports_custom_name_email_and_domain
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.anonymous(
          generate_name: ->(_ctx) { "Guest Bee" },
          generate_random_email: -> { "guest@example.test" }
        )
      ]
    )

    result = auth.api.sign_in_anonymous

    assert_equal "Guest Bee", result[:user]["name"]
    assert_equal "guest@example.test", result[:user]["email"]

    domain_auth = build_auth(plugins: [BetterAuth::Plugins.anonymous(email_domain_name: "anon.example")])
    domain_result = domain_auth.api.sign_in_anonymous
    assert_match(/\Atemp-[0-9a-f]{32}@anon\.example\z/, domain_result[:user]["email"])
  end

  def test_anonymous_sign_in_rejects_invalid_generated_email_and_repeat_anonymous_session
    invalid_auth = build_auth(plugins: [BetterAuth::Plugins.anonymous(generate_random_email: -> { "not-an-email" })])

    invalid = assert_raises(BetterAuth::APIError) do
      invalid_auth.api.sign_in_anonymous
    end
    assert_equal 400, invalid.status_code
    assert_equal BetterAuth::Plugins::ANONYMOUS_ERROR_CODES["INVALID_EMAIL_FORMAT"], invalid.message

    auth = build_auth(plugins: [BetterAuth::Plugins.anonymous])
    _status, headers, _body = auth.api.sign_in_anonymous(as_response: true)
    cookie = cookie_header(headers.fetch("set-cookie"))

    repeated = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_anonymous(headers: {"cookie" => cookie})
    end
    assert_equal 400, repeated.status_code
    assert_equal BetterAuth::Plugins::ANONYMOUS_ERROR_CODES["ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"], repeated.message
  end

  def test_delete_anonymous_user_removes_user_session_and_cookie
    auth = build_auth(plugins: [BetterAuth::Plugins.anonymous])
    _status, headers, _body = auth.api.sign_in_anonymous(as_response: true)
    cookie = cookie_header(headers.fetch("set-cookie"))
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    status, response_headers, body = auth.api.delete_anonymous_user(headers: {"cookie" => cookie}, as_response: true)

    assert_equal 200, status
    assert_equal({"success" => true}, JSON.parse(body.join))
    assert_nil auth.context.internal_adapter.find_user_by_id(user_id)
    assert_nil auth.api.get_session(headers: {"cookie" => cookie})
    assert_includes response_headers.fetch("set-cookie"), "better-auth.session_token="
  end

  def test_delete_anonymous_user_rejects_disabled_or_non_anonymous_users
    disabled = build_auth(plugins: [BetterAuth::Plugins.anonymous(disable_delete_anonymous_user: true)])
    _status, disabled_headers, _body = disabled.api.sign_in_anonymous(as_response: true)
    disabled_cookie = cookie_header(disabled_headers.fetch("set-cookie"))

    disabled_error = assert_raises(BetterAuth::APIError) do
      disabled.api.delete_anonymous_user(headers: {"cookie" => disabled_cookie})
    end
    assert_equal 400, disabled_error.status_code
    assert_equal BetterAuth::Plugins::ANONYMOUS_ERROR_CODES["DELETE_ANONYMOUS_USER_DISABLED"], disabled_error.message

    auth = build_auth(plugins: [BetterAuth::Plugins.anonymous])
    real_cookie = sign_up_cookie(auth, email: "real@example.com")
    forbidden = assert_raises(BetterAuth::APIError) do
      auth.api.delete_anonymous_user(headers: {"cookie" => real_cookie})
    end
    assert_equal 403, forbidden.status_code
    assert_equal BetterAuth::Plugins::ANONYMOUS_ERROR_CODES["USER_IS_NOT_ANONYMOUS"], forbidden.message
  end

  def test_real_sign_in_links_and_deletes_previous_anonymous_user
    link_calls = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.anonymous(
          on_link_account: ->(data) { link_calls << data }
        )
      ]
    )
    auth.api.sign_up_email(body: {email: "linked@example.com", password: "password123", name: "Linked"})
    _status, anon_headers, _body = auth.api.sign_in_anonymous(as_response: true)
    anon_cookie = cookie_header(anon_headers.fetch("set-cookie"))
    anon_user_id = auth.api.get_session(headers: {"cookie" => anon_cookie})[:user]["id"]

    status, real_headers, body = auth.api.sign_in_email(
      headers: {"cookie" => anon_cookie},
      body: {email: "linked@example.com", password: "password123"},
      as_response: true
    )
    data = JSON.parse(body.join)
    real_cookie = cookie_header(real_headers.fetch("set-cookie"))

    assert_equal 200, status
    assert_equal "linked@example.com", data.fetch("user").fetch("email")
    assert_equal false, data.fetch("user").fetch("isAnonymous")
    assert_nil auth.context.internal_adapter.find_user_by_id(anon_user_id)
    assert_equal 1, link_calls.length
    assert_equal anon_user_id, link_calls.first[:anonymous_user][:user]["id"]
    assert_equal data.fetch("user").fetch("id"), link_calls.first[:new_user][:user]["id"]
    assert_equal "linked@example.com", auth.api.get_session(headers: {"cookie" => real_cookie})[:user]["email"]
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Real User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end
