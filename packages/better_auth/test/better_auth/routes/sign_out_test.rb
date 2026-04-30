# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthRoutesSignOutTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_sign_out_without_session_still_returns_success_and_clears_cookies
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    status, headers, body = auth.api.sign_out(as_response: true)

    assert_equal 200, status
    assert_equal({"success" => true}, JSON.parse(body.join))
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_includes headers.fetch("set-cookie"), "Max-Age=0"
  end

  def test_sign_out_deletes_session_clears_cookies_and_runs_delete_hook
    deleted = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      email_and_password: {enabled: true},
      database: :memory,
      database_hooks: {
        session: {
          delete: {
            after: ->(session, _context) { deleted << session["token"] }
          }
        }
      }
    )
    _status, sign_up_headers, _body = auth.api.sign_up_email(
      body: {email: "sign-out-route@example.com", password: "password123", name: "Sign Out"},
      as_response: true
    )
    cookie = cookie_header(sign_up_headers.fetch("set-cookie"))
    session = auth.api.get_session(headers: {"cookie" => cookie})

    status, headers, body = auth.api.sign_out(headers: {"cookie" => cookie}, as_response: true)

    assert_equal 200, status
    assert_equal({"success" => true}, JSON.parse(body.join))
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_includes headers.fetch("set-cookie"), "Max-Age=0"
    assert_includes deleted, session[:session]["token"]
    assert_nil auth.context.internal_adapter.find_session(session[:session]["token"])
  end

  private

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end
