# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module_function

      def legacy_register_endpoint(config)
        Endpoint.new(path: "/mcp/register", method: "POST", metadata: BetterAuth::Plugins.mcp_openapi("legacyRegisterMcpClient", "Register an OAuth2 application using the legacy MCP path", "OAuth2 application registered successfully", BetterAuth::Plugins.mcp_client_schema)) do |ctx|
          ctx.json(register_client(ctx, config), status: 201, headers: no_store_headers)
        end
      end

      def legacy_authorize_endpoint(config)
        Endpoint.new(path: "/mcp/authorize", method: "GET", metadata: BetterAuth::Plugins.mcp_openapi("legacyMcpOAuthAuthorize", "Authorize an OAuth2 request using the legacy MCP path", "Authorization response generated successfully", {type: "object", additionalProperties: true})) do |ctx|
          authorize(ctx, config)
        end
      end

      def legacy_token_endpoint(config)
        Endpoint.new(
          path: "/mcp/token",
          method: "POST",
          metadata: BetterAuth::Plugins.mcp_openapi("legacyMcpOAuthToken", "Exchange OAuth2 code for MCP tokens using the legacy path", "OAuth2 tokens issued successfully", BetterAuth::Plugins.mcp_token_response_schema).merge(allowed_media_types: ["application/x-www-form-urlencoded", "application/json"])
        ) do |ctx|
          ctx.json(token(ctx, config), headers: no_store_headers)
        end
      end

      def legacy_userinfo_endpoint(config)
        Endpoint.new(path: "/mcp/userinfo", method: "GET", metadata: BetterAuth::Plugins.mcp_openapi("legacyMcpOAuthUserinfo", "Get MCP OAuth2 user information using the legacy path", "User information retrieved successfully", BetterAuth::Plugins.mcp_userinfo_schema)) do |ctx|
          ctx.json(userinfo(ctx, config))
        end
      end

      def legacy_jwks_endpoint(config)
        Endpoint.new(path: "/mcp/jwks", method: "GET", metadata: BetterAuth::Plugins.mcp_openapi("legacyMcpJSONWebKeySet", "Get the MCP JSON Web Key Set using the legacy path", "JSON Web Key Set retrieved successfully", BetterAuth::Plugins.mcp_jwks_response_schema)) do |ctx|
          ctx.json(jwks(ctx, config))
        end
      end
    end
  end
end
