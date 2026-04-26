# frozen_string_literal: true

require_relative "better_auth/version"
require_relative "better_auth/core"
require_relative "better_auth/error"
require_relative "better_auth/api_error"
require_relative "better_auth/crypto"
require_relative "better_auth/password"
require_relative "better_auth/configuration"
require_relative "better_auth/schema"
require_relative "better_auth/schema/sql"
require_relative "better_auth/adapters/base"
require_relative "better_auth/adapters/memory"
require_relative "better_auth/adapters/sql"
require_relative "better_auth/adapters/postgres"
require_relative "better_auth/adapters/mysql"
require_relative "better_auth/database_hooks"
require_relative "better_auth/adapters/internal_adapter"
require_relative "better_auth/context"
require_relative "better_auth/session_store"
require_relative "better_auth/cookies"
require_relative "better_auth/session"
require_relative "better_auth/endpoint"
require_relative "better_auth/routes/ok"
require_relative "better_auth/routes/error"
require_relative "better_auth/routes/sign_up"
require_relative "better_auth/routes/sign_in"
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
