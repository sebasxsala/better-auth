# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsMultiSessionTest < Minitest::Test
  SECRET = "phase-seven-secret-with-enough-entropy-123"

  def test_multi_session_tracks_device_sessions_and_switches_active_session
    auth = build_auth(plugins: [BetterAuth::Plugins.multi_session(maximum_sessions: 3)])
    cookie = ""

    cookie = merge_cookie(cookie, sign_up_response(auth, email: "one@example.com"))
    cookie = merge_cookie(cookie, sign_up_response(auth, email: "two@example.com"))
    sessions = auth.api.list_device_sessions(headers: {"cookie" => cookie})

    assert_equal ["one@example.com", "two@example.com"], sessions.map { |entry| entry[:user]["email"] }.sort

    first_token = sessions.find { |entry| entry[:user]["email"] == "one@example.com" }[:session]["token"]
    switched = auth.api.set_active_session(headers: {"cookie" => cookie}, body: {sessionToken: first_token})

    assert_equal "one@example.com", switched[:user]["email"]
  end

  def test_multi_session_revoke_deletes_cookie_and_session
    auth = build_auth(plugins: [BetterAuth::Plugins.multi_session(maximum_sessions: 3)])
    cookie = merge_cookie("", sign_up_response(auth, email: "revoke-one@example.com"))
    cookie = merge_cookie(cookie, sign_up_response(auth, email: "revoke-two@example.com"))
    sessions = auth.api.list_device_sessions(headers: {"cookie" => cookie})
    token = sessions.find { |entry| entry[:user]["email"] == "revoke-one@example.com" }[:session]["token"]

    status, headers, body = auth.api.revoke_device_session(
      headers: {"cookie" => cookie},
      body: {sessionToken: token},
      as_response: true
    )

    assert_equal 200, status
    assert_equal({"status" => true}, JSON.parse(body.join))
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token_multi-#{token.downcase}="
    assert_nil auth.context.internal_adapter.find_session(token)
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end

  def sign_up_response(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Multi User"},
      as_response: true
    )
    headers.fetch("set-cookie")
  end

  def merge_cookie(existing, set_cookie)
    cookies = existing.to_s.split("; ").reject(&:empty?).to_h { |part| part.split("=", 2) }
    set_cookie.lines.each do |line|
      name, value = line.split(";", 2).first.split("=", 2)
      cookies[name] = value
    end
    cookies.map { |name, value| "#{name}=#{value}" }.join("; ")
  end
end
