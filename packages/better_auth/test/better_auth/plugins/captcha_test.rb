# frozen_string_literal: true

require "json"
require "stringio"
require_relative "../../test_helper"

class BetterAuthPluginsCaptchaTest < Minitest::Test
  SECRET = "phase-nine-captcha-secret-with-enough-entropy"

  def test_ignores_unprotected_endpoints_and_requires_response_on_default_endpoints
    auth = build_auth(provider: "cloudflare-turnstile", verifier: ->(_params) { {success: true} })

    ok_status, = auth.call(rack_env("GET", "/api/auth/ok"))
    assert_equal 200, ok_status

    status, _headers, body = auth.call(rack_env("POST", "/api/auth/sign-in/email", body: {email: "a@example.com", password: "password123"}))
    assert_equal 400, status
    assert_equal "Missing CAPTCHA response", JSON.parse(body.join).fetch("message")
  end

  def test_cloudflare_turnstile_posts_json_and_allows_success
    observed = nil
    auth = build_auth(
      provider: "cloudflare-turnstile",
      verifier: ->(params) {
        observed = params
        {success: true}
      }
    )
    auth.api.sign_up_email(body: {email: "captcha@example.com", password: "password123", name: "Captcha"})

    status, _headers, = auth.call(rack_env(
      "POST",
      "/api/auth/sign-in/email",
      body: {email: "captcha@example.com", password: "password123"},
      headers: {"HTTP_X_CAPTCHA_RESPONSE" => "captcha-token", "REMOTE_ADDR" => "203.0.113.10"}
    ))

    assert_equal 200, status
    assert_equal "application/json", observed.fetch(:content_type)
    assert_equal "203.0.113.10", observed.fetch(:payload).fetch("remoteip")
  end

  def test_google_recaptcha_enforces_score_and_form_encoding
    auth = build_auth(
      provider: "google-recaptcha",
      min_score: 0.8,
      verifier: ->(params) {
        assert_equal "application/x-www-form-urlencoded", params.fetch(:content_type)
        {success: true, score: 0.2}
      }
    )
    auth.api.sign_up_email(body: {email: "google-captcha@example.com", password: "password123", name: "Captcha"})

    status, _headers, body = auth.call(rack_env(
      "POST",
      "/api/auth/sign-in/email",
      body: {email: "google-captcha@example.com", password: "password123"},
      headers: {"HTTP_X_CAPTCHA_RESPONSE" => "low-score-token"}
    ))

    assert_equal 403, status
    assert_equal "Captcha verification failed", JSON.parse(body.join).fetch("message")
  end

  def test_hcaptcha_and_captchafox_include_site_key_and_expected_remote_ip_key
    hcaptcha_seen = nil
    hcaptcha = build_auth(provider: "hcaptcha", site_key: "site", verifier: ->(params) {
      hcaptcha_seen = params
      {success: true}
    })
    hcaptcha.api.sign_up_email(body: {email: "hcaptcha@example.com", password: "password123", name: "Captcha"})
    assert_equal 200, hcaptcha.call(rack_env(
      "POST",
      "/api/auth/sign-in/email",
      body: {email: "hcaptcha@example.com", password: "password123"},
      headers: {"HTTP_X_CAPTCHA_RESPONSE" => "token", "REMOTE_ADDR" => "198.51.100.10"}
    )).first
    assert_equal "site", hcaptcha_seen.fetch(:payload).fetch("sitekey")
    assert_equal "198.51.100.10", hcaptcha_seen.fetch(:payload).fetch("remoteip")

    fox_seen = nil
    fox = build_auth(provider: "captchafox", site_key: "fox-site", verifier: ->(params) {
      fox_seen = params
      {success: true}
    })
    fox.api.sign_up_email(body: {email: "fox@example.com", password: "password123", name: "Captcha"})
    assert_equal 200, fox.call(rack_env(
      "POST",
      "/api/auth/sign-in/email",
      body: {email: "fox@example.com", password: "password123"},
      headers: {"HTTP_X_CAPTCHA_RESPONSE" => "token", "REMOTE_ADDR" => "198.51.100.11"}
    )).first
    assert_equal "fox-site", fox_seen.fetch(:payload).fetch("sitekey")
    assert_equal "198.51.100.11", fox_seen.fetch(:payload).fetch("remoteIp")
  end

  def test_service_failure_returns_unknown_error
    auth = build_auth(provider: "cloudflare-turnstile", verifier: ->(_params) { raise "boom" })

    status, _headers, body = auth.call(rack_env(
      "POST",
      "/api/auth/sign-in/email",
      body: {email: "missing@example.com", password: "password123"},
      headers: {"HTTP_X_CAPTCHA_RESPONSE" => "token"}
    ))

    assert_equal 500, status
    assert_equal "Something went wrong", JSON.parse(body.join).fetch("message")
  end

  def build_auth(options)
    BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.captcha(
          provider: options.fetch(:provider),
          secret_key: "secret",
          site_key: options[:site_key],
          min_score: options[:min_score],
          verifier: options.fetch(:verifier)
        )
      ]
    )
  end

  def rack_env(method, path, body: nil, headers: {})
    payload = body ? JSON.generate(body) : ""
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => headers.fetch("REMOTE_ADDR", "127.0.0.1"),
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(payload),
      "CONTENT_TYPE" => body ? "application/json" : nil,
      "CONTENT_LENGTH" => payload.bytesize.to_s
    }.merge(headers).compact
  end
end
