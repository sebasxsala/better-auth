# frozen_string_literal: true

require_relative "better_auth/version"
require_relative "better_auth/core"
require_relative "better_auth/error"
require_relative "better_auth/api_error"
require_relative "better_auth/configuration"
require_relative "better_auth/context"
require_relative "better_auth/endpoint"
require_relative "better_auth/api"
require_relative "better_auth/rate_limiter"
require_relative "better_auth/middleware/origin_check"
require_relative "better_auth/router"
require_relative "better_auth/auth"

module BetterAuth
  def self.auth(options = {})
    Auth.new(options)
  end
end
