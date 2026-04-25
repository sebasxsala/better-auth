# frozen_string_literal: true

module BetterAuth
  class Auth
    attr_reader :handler, :api, :options, :context, :error_codes

    def initialize(options = {})
      @options = Configuration.new(options)
      @context = Context.new(@options)
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
      options.plugins.each_with_object(BASE_ERROR_CODES.dup) do |plugin, codes|
        plugin_codes = plugin[:error_codes] || plugin[:$error_codes] || plugin[:$ERROR_CODES]
        next unless plugin_codes

        plugin_codes.each do |key, value|
          codes[key.to_s.upcase] = value
        end
      end
    end

    def build_endpoints
      plugin_endpoints = options.plugins.each_with_object({}) do |plugin, result|
        result.merge!(plugin.fetch(:endpoints, {}))
      end

      plugin_endpoints.merge(
        ok: Endpoint.new(path: "/ok", method: "GET") { {ok: true} },
        error: Endpoint.new(path: "/error", method: "GET") do |ctx|
          code = ctx.query["code"] || ctx.query[:code] || "ERROR"
          {error: code}
        end
      )
    end
  end
end
