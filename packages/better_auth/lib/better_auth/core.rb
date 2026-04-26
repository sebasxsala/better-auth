# frozen_string_literal: true

module BetterAuth
  module Core
    def self.base_endpoints
      {
        ok: Routes.ok,
        error: Routes.error,
        sign_up_email: Routes.sign_up_email,
        sign_in_email: Routes.sign_in_email
      }
    end
  end
end
