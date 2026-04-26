# frozen_string_literal: true

require "better_auth"
require_relative "rails/version"
require_relative "rails/configuration"
require_relative "rails/migration"
require_relative "rails/active_record_adapter"
require_relative "rails/routing"
require_relative "rails/controller_helpers"
require_relative "rails/railtie" if defined?(::Rails::Railtie)

module BetterAuth
  module Rails
    class << self
      def configuration
        @configuration ||= Configuration.new
      end

      def configure
        yield configuration
        @auth = nil
      end

      def auth
        @auth ||= BetterAuth.auth(configuration.to_auth_options)
      end
    end
  end
end
