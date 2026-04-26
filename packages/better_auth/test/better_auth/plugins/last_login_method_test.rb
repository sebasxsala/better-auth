# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPluginsLastLoginMethodTest < Minitest::Test
  SECRET = "phase-seven-secret-with-enough-entropy-123"

  def test_last_login_method_sets_cookie_on_successful_email_sign_in
    auth = build_auth(plugins: [BetterAuth::Plugins.last_login_method])
    auth.api.sign_up_email(body: {email: "last@example.com", password: "password123", name: "Last"})

    _status, headers, _body = auth.api.sign_in_email(
      body: {email: "last@example.com", password: "password123"},
      as_response: true
    )

    assert_includes headers.fetch("set-cookie"), "better-auth.last_used_login_method=email"
  end

  def test_last_login_method_does_not_set_cookie_on_failed_sign_in
    auth = build_auth(plugins: [BetterAuth::Plugins.last_login_method])
    auth.api.sign_up_email(body: {email: "last-fail@example.com", password: "password123", name: "Last"})

    status, headers, _body = auth.api.sign_in_email(
      body: {email: "last-fail@example.com", password: "wrong-password"},
      as_response: true
    )

    assert_equal 401, status
    refute_includes headers.fetch("set-cookie", ""), "better-auth.last_used_login_method"
  end

  def test_last_login_method_can_store_in_database
    auth = build_auth(plugins: [BetterAuth::Plugins.last_login_method(store_in_database: true)])
    auth.api.sign_up_email(body: {email: "last-db@example.com", password: "password123", name: "Last DB"})

    _status, headers, _body = auth.api.sign_in_email(
      body: {email: "last-db@example.com", password: "password123"},
      as_response: true
    )
    cookie = headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
    session = auth.api.get_session(headers: {"cookie" => cookie}, query: {disableCookieCache: true})

    assert_equal "email", session[:user]["lastLoginMethod"]
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end
end
