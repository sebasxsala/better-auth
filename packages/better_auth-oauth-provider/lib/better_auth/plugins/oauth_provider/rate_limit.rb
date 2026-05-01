# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_provider_rate_limits(config)
      rate_limit = normalize_hash(config[:rate_limit] || {})
      [
        oauth_rate_limit_rule(rate_limit, :token, "/oauth2/token", window: 60, max: 20),
        oauth_rate_limit_rule(rate_limit, :authorize, "/oauth2/authorize", window: 60, max: 30),
        oauth_rate_limit_rule(rate_limit, :introspect, "/oauth2/introspect", window: 60, max: 100),
        oauth_rate_limit_rule(rate_limit, :revoke, "/oauth2/revoke", window: 60, max: 30),
        oauth_rate_limit_rule(rate_limit, :register, "/oauth2/register", window: 60, max: 5),
        oauth_rate_limit_rule(rate_limit, :userinfo, "/oauth2/userinfo", window: 60, max: 60)
      ].compact
    end

    def oauth_rate_limit_rule(rate_limit, key, path, window:, max:)
      override = rate_limit[key]
      return nil if override == false

      override = normalize_hash(override || {})
      {
        path_matcher: ->(request_path) { request_path == path },
        window: override[:window] || window,
        max: override[:max] || max
      }
    end
  end
end
