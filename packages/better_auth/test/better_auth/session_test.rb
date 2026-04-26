# frozen_string_literal: true

require "test_helper"

class BetterAuthSessionTest < Minitest::Test
  SECRET = "phase-four-secret-with-enough-entropy-456"

  def test_find_current_session_from_signed_cookie
    auth = BetterAuth.auth(secret: SECRET, session: {cookie_cache: {enabled: false}})
    user = auth.context.internal_adapter.create_user("name" => "Ada", "email" => "ada@example.com")
    session = auth.context.internal_adapter.create_session(user["id"], false, {"ipAddress" => "127.0.0.1", "userAgent" => "Minitest"})
    ctx = endpoint_context(auth)
    BetterAuth::Cookies.set_session_cookie(ctx, {session: session, user: user}, false)
    request_ctx = endpoint_context(auth, cookie: ctx.response_headers.fetch("set-cookie").lines.first.split(";").first)

    result = BetterAuth::Session.find_current(request_ctx)

    assert_equal session["token"], result[:session]["token"]
    assert_equal user["id"], result[:user]["id"]
  end

  def test_find_current_session_refreshes_expiration_when_update_age_is_reached
    auth = BetterAuth.auth(secret: SECRET, session: {update_age: 0, expires_in: 120, cookie_cache: {enabled: false}})
    user = auth.context.internal_adapter.create_user("name" => "Ada", "email" => "ada@example.com")
    session = auth.context.internal_adapter.create_session(user["id"])
    old_expiration = session["expiresAt"]
    ctx = endpoint_context(auth)
    BetterAuth::Cookies.set_session_cookie(ctx, {session: session, user: user}, false)
    request_ctx = endpoint_context(auth, cookie: ctx.response_headers.fetch("set-cookie").lines.first.split(";").first)

    result = BetterAuth::Session.find_current(request_ctx)

    assert_operator result[:session]["expiresAt"], :>, old_expiration
    assert_includes request_ctx.response_headers.fetch("set-cookie"), "Max-Age=120"
  end

  def test_find_current_session_expires_cookie_when_session_is_missing
    auth = BetterAuth.auth(secret: SECRET, session: {cookie_cache: {enabled: false}})
    ctx = endpoint_context(auth)
    ctx.set_signed_cookie(auth.context.auth_cookies[:session_token].name, "missing-token", SECRET)
    request_ctx = endpoint_context(auth, cookie: ctx.response_headers.fetch("set-cookie").split(";").first)

    assert_nil BetterAuth::Session.find_current(request_ctx)
    assert_includes request_ctx.response_headers.fetch("set-cookie"), "Max-Age=0"
  end

  private

  def endpoint_context(auth, cookie: nil)
    headers = {}
    headers["cookie"] = cookie if cookie
    BetterAuth::Endpoint::Context.new(
      path: "/test",
      method: "GET",
      query: {},
      body: {},
      params: {},
      headers: headers,
      context: auth.context
    )
  end
end
