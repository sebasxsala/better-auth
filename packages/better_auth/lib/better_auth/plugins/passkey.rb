# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def passkey(*args)
      Kernel.require "better_auth/passkey"
      BetterAuth::Plugins.passkey(*args)
    rescue LoadError => error
      raise if error.path && error.path != "better_auth/passkey"

      raise LoadError, "BetterAuth::Plugins.passkey requires the better_auth-passkey gem. Add `gem \"better_auth-passkey\"` and `require \"better_auth/passkey\"`."
    end
  end
end
