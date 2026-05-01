# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module_function

      def legacy_register_endpoint(config)
        Endpoint.new(path: "/mcp/register", method: "POST") do |ctx|
          ctx.json(register_client(ctx, config), status: 201, headers: no_store_headers)
        end
      end

      def legacy_authorize_endpoint(config)
        Endpoint.new(path: "/mcp/authorize", method: "GET") do |ctx|
          authorize(ctx, config)
        end
      end

      def legacy_token_endpoint(config)
        Endpoint.new(path: "/mcp/token", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
          ctx.json(token(ctx, config), headers: no_store_headers)
        end
      end

      def legacy_userinfo_endpoint(config)
        Endpoint.new(path: "/mcp/userinfo", method: "GET") do |ctx|
          ctx.json(userinfo(ctx, config))
        end
      end

      def legacy_jwks_endpoint(config)
        Endpoint.new(path: "/mcp/jwks", method: "GET") do |ctx|
          ctx.json(jwks(ctx, config))
        end
      end
    end
  end
end
