# frozen_string_literal: true

require_relative "test_support"

class BetterAuthAPIKeyRateLimitTest < Minitest::Test
  def test_rate_limit_reports_retry_window_when_request_count_is_exhausted
    now = Time.now
    config = {rate_limit: {enabled: true}}
    record = {
      "rateLimitEnabled" => true,
      "rateLimitTimeWindow" => 60_000,
      "rateLimitMax" => 1,
      "requestCount" => 1,
      "lastRequest" => now - 10
    }

    assert_operator BetterAuth::APIKey::RateLimit.try_again_in(record, config, now), :>, 0
  end

  def test_rate_limit_count_resets_after_window
    now = Time.now
    record = {
      "rateLimitTimeWindow" => 1_000,
      "requestCount" => 9,
      "lastRequest" => now - 2
    }

    assert_equal 1, BetterAuth::APIKey::RateLimit.next_request_count(record, now)
  end
end
