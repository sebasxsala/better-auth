# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsOneTapTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"

  def test_callback_creates_google_oauth_user_and_session
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.one_tap(verify_id_token: google_verifier(
          email: "onetap@example.com",
          email_verified: true,
          name: "One Tap",
          picture: "https://example.com/avatar.png",
          sub: "google-sub-1"
        ))
      ]
    )

    status, headers, body = auth.api.one_tap_callback(
      body: {idToken: "valid-id-token"},
      as_response: true
    )
    data = JSON.parse(body.first)

    assert_equal 200, status
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("token"))
    assert_equal "onetap@example.com", data.dig("user", "email")
    assert_equal true, data.dig("user", "emailVerified")

    account = auth.context.internal_adapter.find_account_by_provider_id("google-sub-1", "google")
    refute_nil account
    assert_equal "valid-id-token", account["idToken"]
  end

  def test_callback_reuses_existing_google_account
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.one_tap(verify_id_token: google_verifier(
          email: "existing@example.com",
          email_verified: true,
          name: "Existing",
          sub: "google-sub-existing"
        ))
      ]
    )
    first = auth.api.one_tap_callback(body: {idToken: "first-token"})

    result = auth.api.one_tap_callback(body: {idToken: "second-token"})

    assert_equal first[:user]["id"], result[:user]["id"]
    assert_equal 1, auth.context.internal_adapter.find_accounts(first[:user]["id"]).length
  end

  def test_callback_links_existing_user_when_google_email_is_verified
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.one_tap(verify_id_token: google_verifier(
          email: "link@example.com",
          email_verified: true,
          name: "Linked",
          sub: "google-sub-link"
        ))
      ]
    )
    auth.api.sign_up_email(body: {email: "link@example.com", password: "password123", name: "Linked"})

    result = auth.api.one_tap_callback(body: {idToken: "verified-token"})

    assert_equal "link@example.com", result[:user]["email"]
    account = auth.context.internal_adapter.find_account_by_provider_id("google-sub-link", "google")
    refute_nil account
    assert_equal "openid,profile,email", account["scope"]
  end

  def test_callback_rejects_untrusted_google_sub_for_existing_user
    auth = build_auth(
      account: {account_linking: {trusted_providers: []}},
      plugins: [
        BetterAuth::Plugins.one_tap(verify_id_token: google_verifier(
          email: "untrusted@example.com",
          email_verified: false,
          name: "Untrusted",
          sub: "google-sub-untrusted"
        ))
      ]
    )
    auth.api.sign_up_email(body: {email: "untrusted@example.com", password: "password123", name: "Untrusted"})

    error = assert_raises(BetterAuth::APIError) do
      auth.api.one_tap_callback(body: {idToken: "unverified-token"})
    end

    assert_equal 401, error.status_code
    assert_equal "Google sub doesn't match", error.message
  end

  def test_callback_respects_disable_signup
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.one_tap(
          disable_signup: true,
          verify_id_token: google_verifier(
            email: "disabled@example.com",
            email_verified: true,
            name: "Disabled",
            sub: "google-sub-disabled"
          )
        )
      ]
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.one_tap_callback(body: {idToken: "valid-id-token"})
    end

    assert_equal 502, error.status_code
    assert_equal "User not found", error.message
  end

  def test_callback_rejects_invalid_token_and_returns_email_error_payload
    invalid = build_auth(plugins: [BetterAuth::Plugins.one_tap])

    error = assert_raises(BetterAuth::APIError) do
      invalid.api.one_tap_callback(body: {idToken: "not-a-jwt"})
    end

    assert_equal 400, error.status_code
    assert_equal "invalid id token", error.message

    no_email = build_auth(
      plugins: [
        BetterAuth::Plugins.one_tap(verify_id_token: ->(_token, _ctx = nil, **_options) { {"sub" => "no-email-sub"} })
      ]
    )

    assert_equal({error: "Email not available in token"}, no_email.api.one_tap_callback(body: {idToken: "valid-id-token"}))
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      social_providers: {google: {client_id: "google-client-id"}}
    }.merge(options))
  end

  def google_verifier(payload)
    normalized = payload.transform_keys(&:to_s)
    ->(_token, _ctx = nil, **_options) { normalized }
  end
end
