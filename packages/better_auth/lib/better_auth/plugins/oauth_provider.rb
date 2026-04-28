# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_provider(*args)
      Kernel.require "better_auth/oauth_provider"
      BetterAuth::Plugins.oauth_provider(*args)
    rescue LoadError => error
      raise if error.path && error.path != "better_auth/oauth_provider"

      raise LoadError, "BetterAuth::Plugins.oauth_provider requires the better_auth-oauth-provider gem. Add `gem \"better_auth-oauth-provider\"` and `require \"better_auth/oauth_provider\"`."
    end
  end
end
