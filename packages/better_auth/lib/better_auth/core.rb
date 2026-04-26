# frozen_string_literal: true

module BetterAuth
  module Core
    def self.base_endpoints
      {
        ok: Routes.ok,
        error: Routes.error
      }
    end
  end
end
