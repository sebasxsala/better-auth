# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def api_key(*args)
      Kernel.require "better_auth/api_key"
      BetterAuth::Plugins.api_key(*args)
    rescue LoadError => error
      raise if error.path && error.path != "better_auth/api_key"

      raise LoadError, "BetterAuth::Plugins.api_key requires the better_auth-api-key gem. Add `gem \"better_auth-api-key\"` and `require \"better_auth/api_key\"`."
    end
  end
end
