# frozen_string_literal: true

require_relative "../../../test_helper"

class OAuthProviderTypesZodTest < Minitest::Test
  Zod = BetterAuth::Plugins::OAuthProvider::Types::Zod

  def test_safe_url_allows_https_loopback_http_and_custom_schemes
    assert Zod.safe_url?("https://example.com/callback")
    assert Zod.safe_url?("http://localhost/callback")
    assert Zod.safe_url?("myapp://callback")
  end

  def test_safe_url_rejects_dangerous_schemes_and_non_loopback_http
    refute Zod.safe_url?("javascript:alert(1)")
    refute Zod.safe_url?("data:text/plain,hello")
    refute Zod.safe_url?("http://example.com/callback")
  end
end
