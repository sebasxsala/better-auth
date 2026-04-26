# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthRoutesSessionTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_get_session_returns_nil_without_cookie
    auth = build_auth

    assert_nil auth.api.get_session
  end

  def test_get_session_returns_current_session_and_user
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "session@example.com")

    result = auth.api.get_session(headers: {"cookie" => cookie})

    assert_equal "session@example.com", result[:user]["email"]
    assert_match(/\A[0-9a-f]{32}\z/, result[:session]["token"])
    assert_equal result[:user]["id"], result[:session]["userId"]
  end

  def test_sign_out_deletes_current_session_and_clears_cookies
    deleted = []
    auth = build_auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database_hooks: {
        session: {
          delete: {
            after: ->(session, _context) { deleted << session["token"] }
          }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "sign-out@example.com")
    session = auth.api.get_session(headers: {"cookie" => cookie})

    status, headers, body = auth.api.sign_out(headers: {"cookie" => cookie}, as_response: true)

    assert_equal 200, status
    assert_equal({"success" => true}, JSON.parse(body.join))
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_includes headers.fetch("set-cookie"), "Max-Age=0"
    assert_includes deleted, session[:session]["token"]
    assert_nil auth.context.internal_adapter.find_session(session[:session]["token"])
    assert_nil auth.api.get_session(headers: {"cookie" => cookie})
  end

  def test_list_sessions_returns_active_sessions_for_current_user
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "list@example.com")
    second_cookie = sign_in_cookie(auth, email: "list@example.com")

    result = auth.api.list_sessions(headers: {"cookie" => second_cookie})

    assert_equal 2, result.length
    assert_equal [auth.api.get_session(headers: {"cookie" => cookie})[:session]["userId"]], result.map { |session| session["userId"] }.uniq
  end

  def test_revoke_session_deletes_only_matching_user_session
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "revoke@example.com")
    second_cookie = sign_in_cookie(auth, email: "revoke@example.com")
    first_token = auth.api.get_session(headers: {"cookie" => first_cookie})[:session]["token"]

    result = auth.api.revoke_session(headers: {"cookie" => second_cookie}, body: {token: first_token})

    assert_equal({status: true}, result)
    assert_nil auth.api.get_session(headers: {"cookie" => first_cookie})
    refute_nil auth.api.get_session(headers: {"cookie" => second_cookie})
  end

  def test_revoke_sessions_deletes_all_current_user_sessions
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "revoke-all@example.com")
    second_cookie = sign_in_cookie(auth, email: "revoke-all@example.com")

    result = auth.api.revoke_sessions(headers: {"cookie" => second_cookie})

    assert_equal({status: true}, result)
    assert_nil auth.api.get_session(headers: {"cookie" => first_cookie})
    assert_nil auth.api.get_session(headers: {"cookie" => second_cookie})
  end

  def test_revoke_other_sessions_keeps_current_session
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "revoke-other@example.com")
    second_cookie = sign_in_cookie(auth, email: "revoke-other@example.com")

    result = auth.api.revoke_other_sessions(headers: {"cookie" => second_cookie})

    assert_equal({status: true}, result)
    assert_nil auth.api.get_session(headers: {"cookie" => first_cookie})
    refute_nil auth.api.get_session(headers: {"cookie" => second_cookie})
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Session User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def sign_in_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_in_email(
      body: {email: email, password: "password123"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end
