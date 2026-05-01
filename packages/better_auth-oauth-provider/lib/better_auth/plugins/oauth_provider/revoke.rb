# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_revoke_endpoint(config)
      Endpoint.new(path: "/oauth2/revoke", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        OAuthProtocol.authenticate_client!(ctx, "oauthClient", store_client_secret: config[:store_client_secret], prefix: config[:prefix])
        body = OAuthProtocol.stringify_keys(ctx.body)
        if body["token_type_hint"].to_s == "access_token" && OAuthProtocol.find_token_by_hint(config[:store], body["token"].to_s, "refresh_token", prefix: config[:prefix])
          raise APIError.new("BAD_REQUEST", message: "invalid_request")
        end
        if body["token_type_hint"].to_s == "refresh_token" && OAuthProtocol.find_token_by_hint(config[:store], body["token"].to_s, "access_token", prefix: config[:prefix])
          raise APIError.new("BAD_REQUEST", message: "invalid_request")
        end
        if (token = OAuthProtocol.find_token_by_hint(config[:store], body["token"].to_s, body["token_type_hint"], prefix: config[:prefix]))
          token["revoked"] = Time.now
        end
        ctx.json({revoked: true})
      end
    end
  end
end
