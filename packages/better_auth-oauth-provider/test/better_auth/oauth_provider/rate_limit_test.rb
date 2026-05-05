# frozen_string_literal: true

require_relative "../../test_helper"

class OAuthProviderRateLimitTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_token_endpoint_rate_limit_is_enforced
    auth = build_rate_limited_auth(token: {window: 60, max: 3})
    client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        scope: "read"
      }
    )

    statuses = 5.times.map do
      token_request_status(auth, client)
    end

    assert_equal [200, 200, 200, 429, 429], statuses
  end

  def test_disabled_token_endpoint_rate_limit_is_not_enforced
    auth = build_rate_limited_auth(token: false)
    client = auth.api.admin_create_o_auth_client(
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        scope: "read"
      }
    )

    statuses = 10.times.map do
      token_request_status(auth, client)
    end

    assert_equal [200] * 10, statuses
  end

  def test_provider_rate_limits_include_continue_consent_and_end_session
    rules = BetterAuth::Plugins.oauth_provider(rate_limit: {}).rate_limit
    paths = ["/oauth2/continue", "/oauth2/consent", "/oauth2/end-session"]

    paths.each do |path|
      assert rules.any? { |rule| rule[:path_matcher].call(path) }, "expected rate limit for #{path}"
    end
  end

  private

  def build_rate_limited_auth(oauth_rate_limit)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: OAuthProviderFlowHelpers::SECRET,
      database: :memory,
      rate_limit: {enabled: true},
      plugins: [
        BetterAuth::Plugins.oauth_provider(
          scopes: ["read"],
          allow_dynamic_client_registration: true,
          rate_limit: oauth_rate_limit
        )
      ]
    )
  end

  def token_request_status(auth, client)
    status, = auth.handler.call(
      rack_env(
        "POST",
        "/api/auth/oauth2/token",
        body: {
          grant_type: "client_credentials",
          client_id: client[:client_id],
          client_secret: client[:client_secret]
        },
        headers: {"REMOTE_ADDR" => "203.0.113.10"}
      )
    )
    status
  end
end
