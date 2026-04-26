# frozen_string_literal: true

module BetterAuth
  class API
    attr_reader :context, :endpoints

    def initialize(context, endpoints)
      @context = context
      @endpoints = endpoints
      define_endpoint_methods
    end

    def call_endpoint(key, input = {})
      endpoint = endpoints.fetch(key.to_sym)
      input = symbolize_keys(input || {})
      endpoint_context = Endpoint::Context.new(
        path: endpoint.path,
        method: Array(endpoint.methods).first,
        query: input[:query] || {},
        body: input[:body] || {},
        params: input[:params] || {},
        headers: input[:headers] || {},
        context: context
      )

      result = run_endpoint_with_hooks(endpoint, endpoint_context)
      format_result(result, input)
    end

    def execute(endpoint, endpoint_context)
      run_endpoint_with_hooks(endpoint, endpoint_context)
    end

    private

    def define_endpoint_methods
      endpoints.each_key do |key|
        method_name = normalize_method_name(key)
        define_singleton_method(method_name) do |input = {}|
          call_endpoint(key, input || {})
        end
      end
    end

    def normalize_method_name(key)
      key.to_s
        .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
        .tr("-", "_")
        .downcase
        .to_sym
    end

    def run_endpoint_with_hooks(endpoint, endpoint_context)
      before = run_before_hooks(endpoint_context)
      return normalize_short_circuit(before, endpoint_context) if before

      result = begin
        endpoint.call(endpoint_context)
      rescue APIError => error
        Endpoint::Result.new(
          response: error,
          status: error.status_code,
          headers: Endpoint::Result.merge_headers(endpoint_context.response_headers, error.headers)
        )
      end

      return result if result.raw_response?

      endpoint_context.returned = result.response
      endpoint_context.response_headers = result.headers.dup

      after_result = run_after_hooks(endpoint_context)
      result.response = after_result.response
      result.headers = after_result.headers
      result.status = after_result.status if after_result.status
      result
    rescue APIError => error
      Endpoint::Result.new(response: error, status: error.status_code, headers: error.headers)
    end

    def run_before_hooks(endpoint_context)
      before_hooks.each do |hook|
        next unless hook_matches?(hook, endpoint_context)

        result = hook[:handler].call(endpoint_context)
        next unless result

        context_data = fetch_key(result, :context)
        if result.is_a?(Hash) && context_data.is_a?(Hash)
          endpoint_context.merge_context!(context_data)
          next
        end

        return result
      end

      nil
    end

    def run_after_hooks(endpoint_context)
      result = Endpoint::Result.new(
        response: endpoint_context.returned,
        status: endpoint_context.status,
        headers: endpoint_context.response_headers
      )

      after_hooks.each do |hook|
        next unless hook_matches?(hook, endpoint_context)

        hook_result = begin
          hook[:handler].call(endpoint_context)
        rescue APIError => error
          error
        end

        result.headers = endpoint_context.response_headers.dup

        next unless hook_result

        normalized = Endpoint::Result.from_value(hook_result, endpoint_context)
        result.response = normalized.response
        result.status = normalized.status
        result.headers = normalized.headers
        endpoint_context.returned = result.response
        endpoint_context.response_headers = result.headers
      end

      result
    end

    def normalize_short_circuit(value, endpoint_context)
      Endpoint::Result.from_value(value, endpoint_context)
    rescue APIError => error
      Endpoint::Result.new(response: error, status: error.status_code, headers: error.headers)
    end

    def format_result(result, input)
      return result.to_rack_response if result.raw_response?

      if result.response.is_a?(APIError)
        return error_response(result.response, headers: result.headers) if input[:as_response]

        raise result.response
      end

      return result.to_rack_response if input[:as_response]

      if input[:return_headers]
        output = {
          headers: result.headers,
          response: result.response
        }
        output[:status] = result.status if input[:return_status]
        return output
      end

      return {response: result.response, status: result.status} if input[:return_status]

      result.response
    end

    def error_response(error, headers: {})
      Endpoint::Result.new(
        response: error.to_h,
        status: error.status_code,
        headers: Endpoint::Result.merge_headers(headers, error.headers)
      ).to_rack_response
    end

    def before_hooks
      hooks = []
      user_before = context.options.hooks&.fetch(:before, nil)
      hooks << {matcher: ->(_ctx) { true }, handler: user_before} if user_before
      hooks.concat(plugin_hooks(:before))
      hooks
    end

    def after_hooks
      hooks = []
      user_after = context.options.hooks&.fetch(:after, nil)
      hooks << {matcher: ->(_ctx) { true }, handler: user_after} if user_after
      hooks.concat(plugin_hooks(:after))
      hooks
    end

    def plugin_hooks(type)
      context.options.plugins.flat_map do |plugin|
        hooks = plugin.dig(:hooks, type)
        Array(hooks).map do |hook|
          {
            matcher: hook[:matcher] || ->(_ctx) { true },
            handler: hook[:handler]
          }
        end
      end.compact
    end

    def hook_matches?(hook, endpoint_context)
      matcher = hook[:matcher] || ->(_ctx) { true }
      matcher.call(endpoint_context)
    end

    def fetch_key(hash, key)
      return unless hash.is_a?(Hash)

      hash[key] || hash[key.to_s]
    end

    def symbolize_keys(value)
      return value unless value.is_a?(Hash)

      value.each_with_object({}) do |(key, object_value), result|
        result[normalize_key(key)] = object_value.is_a?(Hash) ? symbolize_keys(object_value) : object_value
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
