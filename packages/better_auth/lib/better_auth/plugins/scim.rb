# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def scim(*args)
      Kernel.require "better_auth/scim"
      BetterAuth::Plugins.scim(*args)
    rescue LoadError => error
      raise if error.path && error.path != "better_auth/scim"

      raise LoadError, "BetterAuth::Plugins.scim requires the better_auth-scim gem. Add `gem \"better_auth-scim\"` and `require \"better_auth/scim\"`."
    end
  end
end
