# frozen_string_literal: true

require "jwt"
require_relative "../../test_helper"

class BetterAuthPluginsJWTTest < Minitest::Test
  SECRET = "phase-seven-secret-with-enough-entropy-123"

  def test_jwt_plugin_issues_token_header_and_jwks
    auth = build_auth(plugins: [BetterAuth::Plugins.jwt])
    cookie = sign_up_cookie(auth, email: "jwt@example.com")

    _status, headers, _body = auth.api.get_session(headers: {"cookie" => cookie}, as_response: true)
    token = headers.fetch("set-auth-jwt")
    jwks = auth.api.get_jwks

    assert_equal 1, jwks[:keys].length
    decoded, header = JWT.decode(token, BetterAuth::Plugins::JWT.public_key(jwks[:keys].first), true, algorithm: "RS256")
    assert_equal "jwt@example.com", decoded.fetch("email")
    assert_equal decoded.fetch("id"), decoded.fetch("sub")
    assert_equal jwks[:keys].first[:kid], header.fetch("kid")
  end

  def test_jwt_plugin_token_sign_and_verify_endpoints
    auth = build_auth(plugins: [BetterAuth::Plugins.jwt(jwt: {issuer: "https://issuer.example", audience: "ruby"})])
    cookie = sign_up_cookie(auth, email: "jwt-token@example.com")

    issued = auth.api.get_token(headers: {"cookie" => cookie})
    verified = auth.api.verify_jwt(body: {token: issued[:token], issuer: "https://issuer.example"})
    signed = auth.api.sign_jwt(body: {payload: {sub: "manual", aud: "ruby", iss: "https://issuer.example"}})

    assert_equal "jwt-token@example.com", verified[:payload]["email"]
    assert_match(/\A[\w-]+\.[\w-]+\.[\w-]+\z/, signed[:token])
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "JWT User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
