# frozen_string_literal: true

require "uri"
require_relative "../test_helper"

class BetterAuthSocialProvidersTest < Minitest::Test
  def test_google_authorization_url_shape
    provider = BetterAuth::SocialProviders.google(client_id: "google-id", client_secret: "google-secret")

    url = provider.fetch(:create_authorization_url).call(
      state: "state-1",
      code_verifier: "verifier-1",
      redirect_uri: "http://localhost:3000/api/auth/callback/google",
      scopes: ["openid", "email", "profile"],
      loginHint: "ada@example.com"
    )

    assert_equal "google", provider.fetch(:id)
    assert_includes url, "https://accounts.google.com/o/oauth2/v2/auth"
    assert_includes url, "client_id=google-id"
    assert_includes url, "scope=openid+email+profile"
    assert_includes url, "state=state-1"
    assert_includes url, "code_challenge="
    assert_includes url, "code_challenge_method=S256"
    assert_includes url, "login_hint=ada%40example.com"
  end

  def test_github_authorization_url_shape
    provider = BetterAuth::SocialProviders.github(client_id: "github-id", client_secret: "github-secret")

    url = provider.fetch(:create_authorization_url).call(
      state: "state-1",
      redirect_uri: "http://localhost:3000/api/auth/callback/github",
      scopes: ["user:email"]
    )

    assert_equal "github", provider.fetch(:id)
    assert_includes url, "https://github.com/login/oauth/authorize"
    assert_includes url, "client_id=github-id"
    assert_includes url, "scope=user%3Aemail"
  end

  def test_factories_exist_for_selected_common_providers
    assert_equal "gitlab", BetterAuth::SocialProviders.gitlab(client_id: "id", client_secret: "secret").fetch(:id)
    assert_equal "discord", BetterAuth::SocialProviders.discord(client_id: "id", client_secret: "secret").fetch(:id)
    assert_equal "apple", BetterAuth::SocialProviders.apple(client_id: "id", client_secret: "secret").fetch(:id)
    assert_equal "microsoft-entra-id",
      BetterAuth::SocialProviders.microsoft_entra_id(client_id: "id", client_secret: "secret", tenant_id: "common").fetch(:id)
  end
end
