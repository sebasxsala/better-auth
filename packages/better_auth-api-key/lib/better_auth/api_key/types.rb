# frozen_string_literal: true

module BetterAuth
  module APIKey
    module Types
      API_KEY_TABLE_NAME = "apikey"

      module_function

      def record_reference_id(record)
        record["referenceId"] || record[:referenceId] || record["userId"] || record[:userId]
      end

      def record_user_id(record)
        record["userId"] || record[:userId] || (BetterAuth::APIKey::Routes.default_config_id?(record["configId"] || record[:configId]) && (record["referenceId"] || record[:referenceId]))
      end

      def record_config_id(record)
        record["configId"] || record[:configId] || "default"
      end

      def default_permissions(config, reference_id, ctx)
        permissions = config.dig(:permissions, :default_permissions) || config[:default_permissions]
        return permissions.call(reference_id, ctx) if permissions.respond_to?(:call)

        permissions
      end
    end
  end
end
