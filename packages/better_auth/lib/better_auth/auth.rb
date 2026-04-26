# frozen_string_literal: true

module BetterAuth
  class Auth
    attr_reader :handler, :api, :options, :context, :error_codes

    def initialize(options = {})
      @options = Configuration.new(options)
      @context = Context.new(@options)
      @context.set_adapter(build_adapter)
      @context.set_internal_adapter(Adapters::InternalAdapter.new(@context.adapter, @options))
      @plugin_registry = PluginRegistry.new(@context)
      @plugin_registry.run_init!
      @error_codes = build_error_codes
      @endpoints = build_endpoints
      Router.check_endpoint_conflicts(@options, @options.logger)
      @api = API.new(@context, @endpoints)
      @handler = Router.new(@context, @endpoints)
    end

    def call(env)
      handler.call(env)
    end

    private

    def build_error_codes
      @plugin_registry.error_codes(BASE_ERROR_CODES)
    end

    def build_adapter
      return Adapters::Memory.new(options) if options.database.nil? || options.database == :memory
      return options.database.call(options) if options.database.respond_to?(:call)

      options.database
    end

    def build_endpoints
      Core.base_endpoints.merge(@plugin_registry.endpoints)
    end
  end
end
