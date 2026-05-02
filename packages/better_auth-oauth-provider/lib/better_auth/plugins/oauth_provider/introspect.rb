# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_introspect_endpoint(config)
      Endpoint.new(path: "/oauth2/introspect", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        client = OAuthProtocol.authenticate_client!(ctx, "oauthClient", store_client_secret: config[:store_client_secret], prefix: config[:prefix])
        body = OAuthProtocol.stringify_keys(ctx.body)
        token = OAuthProtocol.find_token_by_hint(config[:store], body["token"].to_s, body["token_type_hint"], prefix: config[:prefix])
        active = token && !token["revoked"] && (!token["expiresAt"] || token["expiresAt"] > Time.now)
        if active
          next ctx.json({
            active: true,
            client_id: token["clientId"],
            scope: OAuthProtocol.scope_string(token["scope"] || token["scopes"]),
            sub: token["subject"] || token.dig("user", "id"),
            iss: token["issuer"],
            iat: token["issuedAt"]&.to_i,
            exp: token["expiresAt"]&.to_i,
            sid: token["sessionId"],
            aud: token["audience"]
          })
        end

        jwt = oauth_introspect_jwt_access_token(ctx, client, body["token"].to_s)
        ctx.json(jwt || {active: false})
      end
    end

    def oauth_jwt_access_token?(config, audience)
      !!audience && !config[:disable_jwt_plugin] && !config[:disable_jwt_access_tokens]
    end

    def oauth_introspect_jwt_access_token(ctx, client, token)
      payload = ::JWT.decode(token, ctx.context.secret, true, algorithm: "HS256").first
      client_data = OAuthProtocol.stringify_keys(client)
      return nil unless payload["azp"] == client_data["clientId"]

      {
        active: true,
        client_id: payload["azp"],
        scope: payload["scope"],
        sub: payload["sub"],
        aud: payload["aud"],
        exp: payload["exp"]
      }.compact
    rescue ::JWT::DecodeError
      nil
    end
  end
end
