# frozen_string_literal: true

module BetterAuth
  module Routes
    REQUEST_EMAIL_PATTERN = /\A[^@\s]+@[^@\s]+\.[^@\s]+\z/

    def self.request_body_schema(required_strings: [], required_nonempty_strings: [], email_strings: [], optional_strings: [])
      ->(body) {
        data = request_validation_hash(body)
        return false unless required_strings.all? { |key| request_string?(data, key) }
        return false unless required_nonempty_strings.all? { |key| request_string?(data, key) && !data[request_storage_key(key)].empty? }
        return false unless email_strings.all? { |key| request_string?(data, key) && REQUEST_EMAIL_PATTERN.match?(data[request_storage_key(key)]) }
        return false unless optional_strings.all? { |key| !data.key?(request_storage_key(key)) || request_string?(data, key) }

        data
      }
    end

    def self.request_query_schema(optional_strings: [])
      ->(query) {
        data = request_validation_hash(query)
        return false unless optional_strings.all? { |key| !data.key?(request_storage_key(key)) || request_string?(data, key) }

        data
      }
    end

    def self.request_validation_hash(value)
      return {} unless value.is_a?(Hash)

      value.each_with_object({}) do |(key, object_value), result|
        result[request_storage_key(key)] = object_value
      end
    end

    def self.request_string?(data, key)
      data[request_storage_key(key)].is_a?(String)
    end

    def self.request_storage_key(key)
      key.to_s
        .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
        .tr("-", "_")
        .downcase
        .split("_")
        .then { |parts| ([parts.first] + parts.drop(1).map(&:capitalize)).join }
    end
  end
end
