# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def stripe(*args)
      Kernel.require "better_auth/stripe"
      BetterAuth::Plugins.stripe(*args)
    rescue LoadError => error
      raise if error.path && error.path != "better_auth/stripe"

      raise LoadError, "BetterAuth::Plugins.stripe requires the better_auth-stripe gem. Add `gem \"better_auth-stripe\"` and `require \"better_auth/stripe\"`."
    end
  end
end
