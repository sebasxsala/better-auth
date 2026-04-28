# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def sso(*args)
      Kernel.require "better_auth/sso"
      BetterAuth::Plugins.sso(*args)
    rescue LoadError => error
      raise if error.path && error.path != "better_auth/sso"

      raise LoadError, "BetterAuth::Plugins.sso requires the better_auth-sso gem. Add `gem \"better_auth-sso\"` and `require \"better_auth/sso\"`."
    end
  end
end
