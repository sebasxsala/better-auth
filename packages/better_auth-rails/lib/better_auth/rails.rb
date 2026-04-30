# frozen_string_literal: true

require "better_auth"
require_relative "rails/version"
require_relative "rails/option_builder"
require_relative "rails/configuration"
require_relative "rails/migration"
require_relative "rails/active_record_adapter"
require_relative "rails/mounted_app"
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

      def auth(overrides = nil)
        options = configuration.to_auth_options
        return @auth ||= BetterAuth.auth(options) if overrides.nil? || overrides.empty?

        BetterAuth.auth(options.merge(overrides))
      end
    end
  end
end
