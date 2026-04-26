# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def open_api(options = {})
      config = {path: "/reference", theme: "default"}.merge(normalize_hash(options))

      Plugin.new(
        id: "open-api",
        endpoints: {
          generate_open_api_schema: Endpoint.new(path: "/open-api/generate-schema", method: "GET") do |ctx|
            ctx.json(open_api_schema(ctx.context))
          end,
          open_api_reference: Endpoint.new(path: config[:path], method: "GET", metadata: {hide: true}) do |ctx|
            raise APIError.new("NOT_FOUND") if config[:disable_default_reference]

            [200, {"content-type" => "text/html"}, [open_api_html(open_api_schema(ctx.context), config)]]
          end
        },
        options: config
      )
    end

    def open_api_schema(context)
      endpoints = Core.base_endpoints.merge(context.options.plugins.each_with_object({}) { |plugin, result| result.merge!(plugin.endpoints) })
      {
        openapi: "3.1.0",
        info: {
          title: "Better Auth API",
          version: context.version
        },
        paths: open_api_paths(endpoints),
        components: {
          schemas: open_api_components(context.options)
        }
      }
    end

    def open_api_paths(endpoints)
      endpoints.values.each_with_object({}) do |endpoint, paths|
        next unless endpoint.path
        next if endpoint.metadata[:hide]

        paths[endpoint.path] ||= {}
        endpoint.methods.reject { |method| method == "*" }.each do |method|
          paths[endpoint.path][method.downcase.to_sym] = {
            operationId: operation_id(endpoint.path, method),
            responses: {
              "200" => {description: "Success"}
            }
          }.tap do |operation|
            operation[:requestBody] = generic_request_body(endpoint.path) if %w[POST PUT PATCH DELETE].include?(method)
          end
        end
      end
    end

    def generic_request_body(path)
      properties = {}
      required = []
      if path == "/sign-in/social"
        properties[:provider] = {type: "string"}
        properties[:idToken] = {
          type: ["object", "null"],
          properties: {
            token: {type: "string"},
            accessToken: {type: ["string", "null"]},
            refreshToken: {type: ["string", "null"]}
          },
          required: ["token"]
        }
        required << "provider"
      end

      {
        required: !required.empty?,
        content: {
          "application/json" => {
            schema: {
              type: "object",
              properties: properties,
              required: required
            }
          }
        }
      }
    end

    def open_api_components(options)
      Schema.auth_tables(options).each_with_object({}) do |(model, table), schemas|
        name = model.to_s.split(/[_-]/).map(&:capitalize).join
        schemas[name.to_sym] = schema_for_table(table)
      end
    end

    def schema_for_table(table)
      required = []
      properties = table[:fields].each_with_object({}) do |(field, attributes), result|
        result[field.to_sym] = field_schema(attributes)
        required << field if attributes[:required]
      end
      {type: "object", properties: properties, required: required}
    end

    def field_schema(attributes)
      type = case attributes[:type].to_s
      when "date" then "string"
      when "number" then "number"
      when "boolean" then "boolean"
      else "string"
      end
      schema = {type: type}
      schema[:format] = "date-time" if attributes[:type].to_s == "date"
      schema[:default] = attributes[:default_value] unless attributes[:default_value].respond_to?(:call) || !attributes.key?(:default_value)
      schema
    end

    def operation_id(path, method)
      "#{method.downcase}_#{path.gsub(%r{[^a-zA-Z0-9]+}, "_").sub(/\A_/, "").sub(/_\z/, "")}"
    end

    def open_api_html(schema, config)
      nonce = config[:nonce] ? " nonce=\"#{config[:nonce]}\"" : ""
      <<~HTML
        <!doctype html>
        <html>
          <head>
            <title>Scalar API Reference</title>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1" />
          </head>
          <body>
            <script id="api-reference" type="application/json">#{JSON.generate(schema)}</script>
            <script#{nonce}>window.scalarTheme = "#{config[:theme]}";</script>
            <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"#{nonce}></script>
          </body>
        </html>
      HTML
    end
  end
end
