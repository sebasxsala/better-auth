# frozen_string_literal: true

require "json"
require "uri"
require_relative "../../test_helper"

class BetterAuthPluginsMagicLinkTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"

  def test_magic_link_sends_and_verifies_existing_user
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.magic_link(send_magic_link: ->(data, _ctx = nil) { sent << data })
      ]
    )
    auth.api.sign_up_email(body: {email: "magic@example.com", password: "password123", name: "Magic"})

    assert_equal({status: true}, auth.api.sign_in_magic_link(body: {email: "magic@example.com", callbackURL: "/dashboard"}))
    assert_equal "magic@example.com", sent.first[:email]
    assert_includes sent.first[:url], "http://localhost:3000/api/auth/magic-link/verify"
    assert_includes sent.first[:url], "callbackURL=%2Fdashboard"

    status, headers, _body = auth.api.magic_link_verify(
      query: {token: sent.first[:token], callbackURL: "/dashboard"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="

    reused = auth.api.magic_link_verify(query: {token: sent.first[:token]}, as_response: true)
    assert_equal 302, reused.first
    assert_includes reused[1].fetch("location"), "error=INVALID_TOKEN"
  end

  def test_magic_link_signs_up_new_user_and_verifies_email
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.magic_link(send_magic_link: ->(data, _ctx = nil) { sent << data })
      ]
    )

    auth.api.sign_in_magic_link(body: {email: "new-magic@example.com", name: "New Magic"})
    result = auth.api.magic_link_verify(query: {token: sent.first[:token]})

    assert_match(/\A[0-9a-f]{32}\z/, result[:token])
    assert_equal "new-magic@example.com", result[:user]["email"]
    assert_equal "New Magic", result[:user]["name"]
    assert_equal true, result[:user]["emailVerified"]
  end

  def test_magic_link_verifies_existing_unverified_user
    sent = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.magic_link(send_magic_link: ->(data, _ctx = nil) { sent << data })
      ]
    )
    auth.api.sign_up_email(body: {email: "unverified-magic@example.com", password: "password123", name: "Unverified"})
    user = auth.context.internal_adapter.find_user_by_email("unverified-magic@example.com")[:user]
    assert_equal false, user["emailVerified"]

    auth.api.sign_in_magic_link(body: {email: "unverified-magic@example.com"})
    result = auth.api.magic_link_verify(query: {token: sent.first[:token]})

    assert_equal true, result[:user]["emailVerified"]
    updated = auth.context.internal_adapter.find_user_by_email("unverified-magic@example.com")[:user]
    assert_equal true, updated["emailVerified"]
  end

  def test_magic_link_redirects_for_expired_invalid_and_disabled_signup
    sent = []
    expired_auth = build_auth(
      plugins: [
        BetterAuth::Plugins.magic_link(
          expires_in: -1,
          send_magic_link: ->(data, _ctx = nil) { sent << data }
        )
      ]
    )
    expired_auth.api.sign_in_magic_link(body: {email: "expired@example.com"})
    expired = expired_auth.api.magic_link_verify(query: {token: sent.first[:token], errorCallbackURL: "/error-page?foo=bar"}, as_response: true)

    assert_equal 302, expired.first
    assert_includes expired[1].fetch("location"), "/error-page?foo=bar&error=EXPIRED_TOKEN"

    disabled_sent = []
    disabled = build_auth(
      plugins: [
        BetterAuth::Plugins.magic_link(
          disable_sign_up: true,
          send_magic_link: ->(data, _ctx = nil) { disabled_sent << data }
        )
      ]
    )
    disabled.api.sign_in_magic_link(body: {email: "disabled-new@example.com"})
    response = disabled.api.magic_link_verify(query: {token: disabled_sent.first[:token]}, as_response: true)

    assert_equal 302, response.first
    assert_includes response[1].fetch("location"), "error=new_user_signup_disabled"
  end

  def test_magic_link_supports_custom_and_hashed_token_storage
    sent = []
    hashed = build_auth(
      plugins: [
        BetterAuth::Plugins.magic_link(
          store_token: "hashed",
          generate_token: ->(_email) { "hashed-token" },
          send_magic_link: ->(data, _ctx = nil) { sent << data }
        )
      ]
    )

    hashed.api.sign_in_magic_link(body: {email: "hash@example.com"})
    assert hashed.context.internal_adapter.find_verification_value(BetterAuth::Crypto.sha256("hashed-token", encoding: :base64url))
    assert_nil hashed.context.internal_adapter.find_verification_value("hashed-token")

    custom_sent = []
    custom = build_auth(
      plugins: [
        BetterAuth::Plugins.magic_link(
          store_token: {type: "custom-hasher", hash: ->(token) { "#{token}:stored" }},
          generate_token: ->(_email) { "custom-token" },
          send_magic_link: ->(data, _ctx = nil) { custom_sent << data }
        )
      ]
    )
    custom.api.sign_in_magic_link(body: {email: "custom@example.com"})

    assert_equal "custom-token", custom_sent.first[:token]
    assert custom.context.internal_adapter.find_verification_value("custom-token:stored")
  end

  def test_magic_link_rejects_untrusted_verify_callback_url
    sent = []
    auth = build_auth(
      trusted_origins: ["http://localhost:3000"],
      plugins: [
        BetterAuth::Plugins.magic_link(send_magic_link: ->(data, _ctx = nil) { sent << data })
      ]
    )
    auth.api.sign_in_magic_link(body: {email: "origin@example.com"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.magic_link_verify(query: {token: sent.first[:token], callbackURL: "http://malicious.com"})
    end

    assert_equal 403, error.status_code
    assert_equal "Invalid callbackURL", error.message
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end
end
