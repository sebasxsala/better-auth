# frozen_string_literal: true

require "jwt"

module BetterAuth
  module Plugins
    module MCP
      module_function

      def userinfo(ctx, config)
        OAuthProtocol.userinfo(config[:store], ctx.headers["authorization"], prefix: config[:prefix], jwt_secret: ctx.context.secret)
      end

      def session_from_token(ctx, config)
        authorization = ctx.headers["authorization"].to_s
        token_value = authorization.start_with?("Bearer ") ? authorization.delete_prefix("Bearer ").strip : authorization.strip
        return nil if token_value.empty?

        token_record = OAuthProtocol.token_record(config[:store], token_value, prefix: config[:prefix])
        return token_record if token_record

        payload = ::JWT.decode(token_value, ctx.context.secret, true, algorithm: "HS256").first
        {
          "clientId" => payload["azp"],
          "userId" => payload["sub"],
          "sessionId" => payload["sid"],
          "scopes" => OAuthProtocol.parse_scopes(payload["scope"]),
          "audience" => payload["aud"],
          "subject" => payload["sub"],
          "expiresAt" => payload["exp"] ? Time.at(payload["exp"].to_i) : nil
        }.compact
      rescue ::JWT::DecodeError
        nil
      end
    end
  end
end
