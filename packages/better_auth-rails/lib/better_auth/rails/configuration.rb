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
        password_hasher
        email_verification
        social_providers
        experimental
        secondary_storage
        database_hooks
        hooks
        on_api_error
        disabled_paths
        logger
      ].freeze
      BLOCK_OPTION_NAMES = %i[
        rate_limit
        session
        account
        user
        verification
        advanced
        email_and_password
        email_verification
        social_providers
        experimental
        database_hooks
        hooks
        on_api_error
      ].freeze

      attr_accessor(*AUTH_OPTION_NAMES)

      BLOCK_OPTION_NAMES.each do |name|
        define_method(name) do |&block|
          value = instance_variable_get(:"@#{name}")
          return value unless block

          builder = OptionBuilder.new(value.is_a?(Hash) ? value : {})
          block.call(builder)
          public_send(:"#{name}=", deep_merge(value.is_a?(Hash) ? value : {}, builder.to_h))
        end
      end

      def initialize
        @base_path = BetterAuth::Configuration::DEFAULT_BASE_PATH
        @plugins = []
        @trusted_origins = []
        @database = ->(options) { ActiveRecordAdapter.new(options) }
      end

      def database_adapter=(adapter)
        case adapter&.to_sym
        when :active_record
          self.database = ->(options) { ActiveRecordAdapter.new(options) }
        else
          raise ArgumentError, "Unsupported database_adapter: #{adapter.inspect}. Use :active_record or assign a custom adapter with config.database = ..."
        end
      end

      def to_auth_options
        AUTH_OPTION_NAMES.each_with_object({}) do |name, options|
          value = public_send(name)
          next if value.nil?
          next if value.respond_to?(:empty?) && value.empty?

          options[name] = value
        end
      end

      private

      def deep_merge(base, override)
        base.merge(override) do |_key, old_value, new_value|
          if old_value.is_a?(Hash) && new_value.is_a?(Hash)
            deep_merge(old_value, new_value)
          else
            new_value
          end
        end
      end
    end
  end
end
