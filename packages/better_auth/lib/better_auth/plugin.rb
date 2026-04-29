# frozen_string_literal: true

module BetterAuth
  class Plugin
    FIELDS = [
      :id,
      :init,
      :endpoints,
      :middlewares,
      :hooks,
      :schema,
      :migrations,
      :options,
      :version,
      :client,
      :rate_limit,
      :error_codes,
      :on_request,
      :on_response,
      :adapter
    ].freeze

    attr_reader(*FIELDS)

    def self.coerce(value)
      return value if value.is_a?(self)

      new(value || {})
    end

    def initialize(data = {}, **keywords)
      data = data.to_h if data.respond_to?(:to_h) && !data.is_a?(Hash)
      input = (data || {}).merge(keywords)
      raw = normalize_hash(input)

      @id = raw[:id].to_s
      @init = raw[:init]
      @endpoints = normalize_endpoint_keys(raw[:endpoints] || {})
      @middlewares = normalize_middlewares(raw[:middlewares] || [])
      @hooks = normalize_hooks(raw[:hooks] || {})
      @schema = raw[:schema] || {}
      @migrations = raw[:migrations] || {}
      @options = raw[:options] || {}
      @version = raw[:version]
      @client = stringify_hash(input[:client] || input["client"])
      @rate_limit = Array(raw[:rate_limit])
      @error_codes = normalize_error_codes(raw)
      @on_request = raw[:on_request]
      @on_response = raw[:on_response]
      @adapter = raw[:adapter]
    end

    def [](key)
      to_h[normalize_key(key)]
    end

    def fetch(key, *default, &block)
      normalized = normalize_key(key)
      return to_h.fetch(normalized, *default, &block) if default.any? || block

      to_h.fetch(normalized)
    end

    def dig(*keys)
      keys.reduce(to_h) do |value, key|
        return nil unless value.respond_to?(:[])

        value[normalize_key(key)] || value[key]
      end
    end

    def merge_options!(defaults)
      @options = deep_merge(@options, normalize_hash(defaults || {}))
    end

    def to_h
      FIELDS.each_with_object({}) do |field, result|
        result[field] = public_send(field)
      end
    end

    private

    def normalize_endpoint_keys(value)
      normalize_hash(value).each_with_object({}) do |(key, endpoint), result|
        result[normalize_key(key)] = endpoint
      end
    end

    def normalize_middlewares(value)
      Array(value).map { |middleware| normalize_hash(middleware) }
    end

    def normalize_hooks(value)
      data = normalize_hash(value)
      {
        before: Array(data[:before]).map { |hook| normalize_hash(hook) },
        after: Array(data[:after]).map { |hook| normalize_hash(hook) }
      }
    end

    def normalize_error_codes(raw)
      codes = raw[:error_codes] || raw[:ERROR_CODES] || raw[:$ERROR_CODES]
      normalize_hash(codes || {}).transform_keys { |key| key.to_s.upcase }
    end

    def normalize_hash(value)
      return {} unless value.is_a?(Hash)

      value.each_with_object({}) do |(key, object), result|
        result[normalize_key(key)] = object.is_a?(Hash) ? normalize_hash(object) : object
      end
    end

    def stringify_hash(value)
      return nil unless value.is_a?(Hash)

      value.each_with_object({}) do |(key, object), result|
        result[key.to_s] = object.is_a?(Hash) ? stringify_hash(object) : object
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
