# frozen_string_literal: true

require "better_auth"
require_relative "hanami/version"
require_relative "hanami/configuration"
require_relative "hanami/mounted_app"
require_relative "hanami/routing"
require_relative "hanami/migration"
require_relative "hanami/sequel_adapter"
require_relative "hanami/action_helpers"
require_relative "hanami/generators/install_generator"
require_relative "hanami/generators/migration_generator"
require_relative "hanami/generators/relation_generator"

module BetterAuth
  module Hanami
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
