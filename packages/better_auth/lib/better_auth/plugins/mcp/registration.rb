# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module_function

      def register_client(ctx, config)
        set_cors_headers(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        body["token_endpoint_auth_method"] ||= "none"
        body["grant_types"] ||= [OAuthProtocol::AUTH_CODE_GRANT, OAuthProtocol::REFRESH_GRANT]
        body["response_types"] ||= ["code"]
        body["require_pkce"] = true unless body.key?("require_pkce") || body.key?("requirePKCE")

        OAuthProtocol.create_client(
          ctx,
          model: "oauthClient",
          body: body,
          default_auth_method: "none",
          store_client_secret: config[:store_client_secret],
          default_scopes: config[:scopes],
          allowed_scopes: config[:scopes],
          prefix: config[:prefix],
          dynamic_registration: true,
          strip_client_metadata: true
        )
      end
    end
  end
end
