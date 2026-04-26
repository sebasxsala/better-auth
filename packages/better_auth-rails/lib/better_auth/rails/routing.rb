# frozen_string_literal: true

module BetterAuth
  module Rails
    module Routing
      def better_auth(auth: BetterAuth::Rails.auth, at: BetterAuth::Configuration::DEFAULT_BASE_PATH)
        mount auth, at: at
      end
    end
  end
end
