# frozen_string_literal: true

module BetterAuth
  module Rails
    class Configuration
      AUTH_OPTION_NAMES = %i[
        app_name
        base_url
        base_path
        secret
        database
        plugins
        trusted_origins
        rate_limit
        session
        account
        user
        verification
        advanced
        email_and_password
        email_verification
        social_providers
        secondary_storage
        database_hooks
        hooks
        on_api_error
        disabled_paths
        logger
      ].freeze

      attr_accessor(*AUTH_OPTION_NAMES)

      def initialize
        @base_path = BetterAuth::Configuration::DEFAULT_BASE_PATH
        @plugins = []
        @trusted_origins = []
        @database = ->(options) { ActiveRecordAdapter.new(options) }
      end

      def to_auth_options
        AUTH_OPTION_NAMES.each_with_object({}) do |name, options|
          value = public_send(name)
          next if value.nil?
          next if value.respond_to?(:empty?) && value.empty?

          options[name] = value
        end
      end
    end
  end
end
