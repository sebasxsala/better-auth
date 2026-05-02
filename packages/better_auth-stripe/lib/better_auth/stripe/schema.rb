# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Schema
      module_function

      def schema(config)
        custom_schema = custom_schema(config)
        config = BetterAuth::Plugins.normalize_hash((config || {}).reject { |key, _| key.to_s == "schema" })
        base_schema = {
          user: {
            fields: {
              stripeCustomerId: {type: "string", required: false}
            }
          }
        }

        if config.dig(:subscription, :enabled)
          base_schema[:subscription] = {
            fields: {
              plan: {type: "string", required: true},
              referenceId: {type: "string", required: true},
              stripeCustomerId: {type: "string", required: false},
              stripeSubscriptionId: {type: "string", required: false},
              status: {type: "string", required: false, default_value: "incomplete"},
              periodStart: {type: "date", required: false},
              periodEnd: {type: "date", required: false},
              trialStart: {type: "date", required: false},
              trialEnd: {type: "date", required: false},
              cancelAtPeriodEnd: {type: "boolean", required: false, default_value: false},
              cancelAt: {type: "date", required: false},
              canceledAt: {type: "date", required: false},
              endedAt: {type: "date", required: false},
              seats: {type: "number", required: false},
              billingInterval: {type: "string", required: false},
              stripeScheduleId: {type: "string", required: false},
              limits: {type: "json", required: false}
            }
          }
        end

        if config.dig(:organization, :enabled)
          base_schema[:organization] = {fields: {stripeCustomerId: {type: "string", required: false}}}
        end

        custom_schema = custom_schema.except(:subscription) unless config.dig(:subscription, :enabled)
        deep_merge_schema(base_schema, custom_schema)
      end

      def custom_schema(config)
        raw = config && (config[:schema] || config["schema"])
        normalize_custom_schema(raw || {})
      end

      def normalize_custom_schema(value)
        return {} unless value.is_a?(Hash)

        value.each_with_object({}) do |(model_name, model_schema), result|
          normalized_model = BetterAuth::Plugins.normalize_key(model_name)
          result[normalized_model] = normalize_custom_model_schema(model_schema)
        end
      end

      def normalize_custom_model_schema(value)
        return value unless value.is_a?(Hash)

        value.each_with_object({}) do |(key, object), result|
          normalized_key = BetterAuth::Plugins.normalize_key(key)
          result[normalized_key] = if normalized_key == :fields && object.is_a?(Hash)
            object.each_with_object({}) do |(field_name, field_schema), fields|
              fields[field_name] = field_schema
            end
          elsif object.is_a?(Hash)
            BetterAuth::Plugins.normalize_hash(object)
          else
            object
          end
        end
      end

      def deep_merge_schema(base, override)
        base.merge(override) do |_key, old_value, new_value|
          if old_value.is_a?(Hash) && new_value.is_a?(Hash)
            deep_merge_schema(old_value, new_value)
          else
            new_value
          end
        end
      end
    end
  end
end
