# frozen_string_literal: true

module BetterAuth
  module Passkey
    module Schema
      module_function

      def passkey_schema(custom_schema = nil)
        base = {
          passkey: {
            model_name: "passkeys",
            fields: {
              name: {type: "string", required: false},
              publicKey: {type: "string", required: true},
              userId: {type: "string", references: {model: "user", field: "id"}, required: true, index: true},
              credentialID: {type: "string", required: true, index: true},
              counter: {type: "number", required: true},
              deviceType: {type: "string", required: true},
              backedUp: {type: "boolean", required: true},
              transports: {type: "string", required: false},
              createdAt: {type: "date", required: false},
              aaguid: {type: "string", required: false}
            }
          }
        }
        deep_merge_hashes(normalize_hash(base), normalize_hash(custom_schema || {}))
      end

      def deep_merge_hashes(base, override)
        base.merge(override) do |_key, old_value, new_value|
          if old_value.is_a?(Hash) && new_value.is_a?(Hash)
            deep_merge_hashes(old_value, new_value)
          else
            new_value
          end
        end
      end

      def normalize_hash(value)
        return {} unless value.is_a?(Hash)

        value.each_with_object({}) do |(key, object), result|
          result[normalize_key(key)] = object.is_a?(Hash) ? normalize_hash(object) : object
        end
      end

      def normalize_key(key)
        key.to_s
          .delete_prefix("$")
          .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
          .tr("-", "_")
          .downcase
          .to_sym
      end
    end
  end
end
