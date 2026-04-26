# frozen_string_literal: true

module BetterAuth
  class PluginContext
    attr_reader :context, :plugin

    def initialize(context, plugin = nil)
      @context = context
      @plugin = plugin
    end

    def apply!(attributes)
      context.apply_plugin_context!(attributes || {})
    end
  end
end
