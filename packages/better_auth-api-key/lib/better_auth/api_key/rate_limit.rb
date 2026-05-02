# frozen_string_literal: true

module BetterAuth
  module APIKey
    module RateLimit
      module_function

      def try_again_in(record, config, now)
        return nil if config[:rate_limit][:enabled] == false || record["rateLimitEnabled"] == false

        window = record["rateLimitTimeWindow"]
        max = record["rateLimitMax"]
        return nil if window.nil? || max.nil?

        last = Utils.normalize_time(record["lastRequest"])
        return nil unless last

        elapsed_ms = (now - last) * 1000
        return nil if elapsed_ms > window.to_i
        return nil if record["requestCount"].to_i < max.to_i

        (window.to_i - elapsed_ms).ceil
      end

      def counts_requests?(record, config)
        return false if config[:rate_limit][:enabled] == false || record["rateLimitEnabled"] == false

        !record["rateLimitTimeWindow"].nil? && !record["rateLimitMax"].nil?
      end

      def next_request_count(record, now)
        last = Utils.normalize_time(record["lastRequest"])
        window = record["rateLimitTimeWindow"].to_i
        return 1 unless last && window.positive?

        elapsed_ms = (now - last) * 1000
        (elapsed_ms <= window) ? record["requestCount"].to_i + 1 : 1
      end
    end
  end
end
