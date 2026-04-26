# frozen_string_literal: true

module BetterAuth
  class PluginRegistry
    attr_reader :context, :plugins

    def initialize(context)
      @context = context
      @plugins = context.options.plugins
    end

    def run_init!
      plugins.each do |plugin|
        next unless plugin.init

        result = plugin.init.call(context)
        next unless result.is_a?(Hash)

        apply_options(plugin, result[:options] || result["options"])
        PluginContext.new(context, plugin).apply!(result[:context] || result["context"])
      end

      context.refresh_from_options!
      context.set_internal_adapter(Adapters::InternalAdapter.new(context.adapter, context.options))
    end

    def endpoints
      plugins.each_with_object({}) do |plugin, result|
        result.merge!(plugin.endpoints)
      end
    end

    def error_codes(base)
      plugins.each_with_object(base.dup) do |plugin, codes|
        plugin.error_codes.each do |key, value|
          codes[key.to_s.upcase] = value
        end
      end
    end

    private

    def apply_options(plugin, options)
      return unless options.is_a?(Hash)

      normalized = normalize_hash(options)
      plugin.merge_options!(normalized)
      context.options.merge_defaults!(normalized)
    end

    def normalize_hash(value)
      return {} unless value.is_a?(Hash)

      value.each_with_object({}) do |(key, object), result|
        result[normalize_key(key)] = object.is_a?(Hash) ? normalize_hash(object) : object
      end
    end

    def normalize_key(key)
      key.to_s
        .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
        .tr("-", "_")
        .downcase
        .to_sym
    end
  end
end
