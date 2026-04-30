# frozen_string_literal: true

module BetterAuth
  module Rails
    class OptionBuilder
      def initialize(values = {})
        @values = deep_dup(symbolize_keys(values || {}))
      end

      def to_h
        deep_dup(@values)
      end

      def method_missing(name, *args, &block)
        method_name = name.to_s
        if method_name.end_with?("=")
          key = method_name.delete_suffix("=").to_sym
          @values[key] = args.first
        elsif block
          key = method_name.to_sym
          nested = self.class.new(@values[key].is_a?(Hash) ? @values[key] : {})
          yield nested
          @values[key] = nested.to_h
        elsif args.empty?
          @values[method_name.to_sym]
        else
          super
        end
      end

      def respond_to_missing?(_name, _include_private = false)
        true
      end

      private

      def symbolize_keys(value)
        return value unless value.is_a?(Hash)

        value.each_with_object({}) do |(key, object_value), result|
          normalized_key = key.to_s
            .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
            .tr("-", "_")
            .downcase
            .to_sym
          result[normalized_key] = object_value.is_a?(Hash) ? symbolize_keys(object_value) : object_value
        end
      end

      def deep_dup(value)
        return value.transform_values { |entry| deep_dup(entry) } if value.is_a?(Hash)
        return value.map { |entry| deep_dup(entry) } if value.is_a?(Array)

        value
      end
    end
  end
end
