# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsCustomSessionTest < Minitest::Test
  SECRET = "phase-seven-secret-with-enough-entropy-123"

  def test_custom_session_overrides_get_session_response_and_preserves_cookies
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.custom_session(lambda do |session, _ctx|
          {
            user: {
              firstName: session[:user]["name"].split.first,
              email: session[:user]["email"]
            },
            session: session[:session],
            newData: {message: "Hello, World!"}
          }
        end)
      ],
      session: {update_age: 0, cookie_cache: {enabled: true, max_age: 300}}
    )
    cookie = sign_up_cookie(auth, email: "custom@example.com", name: "Ada Lovelace")

    status, headers, body = auth.api.get_session(headers: {"cookie" => cookie}, as_response: true)
    data = JSON.parse(body.join)

    assert_equal 200, status
    assert_equal "Ada", data.fetch("user").fetch("firstName")
    assert_equal({"message" => "Hello, World!"}, data.fetch("newData"))
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_includes headers.fetch("set-cookie"), "better-auth.session_data="
  end

  def test_custom_session_preserves_individual_cookie_max_age_values
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.custom_session(->(session, _ctx) { session })
      ],
      session: {expires_in: 86_400, update_age: 0, cookie_cache: {enabled: true, max_age: 300}}
    )
    cookie = sign_up_cookie(auth, email: "max-age@example.com", name: "Max Age")

    _status, headers, _body = auth.api.get_session(headers: {"cookie" => cookie}, as_response: true)
    cookies = headers.fetch("set-cookie").lines
    token_cookie = cookies.find { |line| line.start_with?("better-auth.session_token=") }
    data_cookie = cookies.find { |line| line.start_with?("better-auth.session_data=") && !line.match?(/Max-Age=0/i) }

    assert token_cookie
    assert data_cookie
    assert_match(/Max-Age=86400/i, token_cookie)
    assert_match(/Max-Age=300/i, data_cookie)
    cookies.each do |line|
      assert_equal 1, line.scan("better-auth.").length
    end
  end

  def test_custom_session_returns_nil_without_invoking_resolver_when_unauthenticated
    called = false
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.custom_session(lambda do |session, _ctx|
          called = true
          session
        end)
      ]
    )

    assert_nil auth.api.get_session
    assert_equal false, called
  end

  def test_custom_session_can_mutate_multi_session_list
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.multi_session(maximum_sessions: 3),
        BetterAuth::Plugins.custom_session(
          ->(session, _ctx) { session.merge(extra: session[:user]["email"]) },
          should_mutate_list_device_sessions_endpoint: true
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "custom-list@example.com", name: "Custom List")

    sessions = auth.api.list_device_sessions(headers: {"cookie" => cookie})

    assert_equal ["custom-list@example.com"], sessions.map { |session| session[:extra] || session["extra"] }
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end

  def sign_up_cookie(auth, email:, name:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: name},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
