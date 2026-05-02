# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module_function

      def token(ctx, config)
        set_cors_headers(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.authenticate_client!(ctx, "oauthClient", store_client_secret: config[:store_client_secret], prefix: config[:prefix])
        audience = validate_resource!(config, body)

        case body["grant_type"]
        when OAuthProtocol::AUTH_CODE_GRANT
          code = OAuthProtocol.consume_code!(
            config[:store],
            body["code"],
            client_id: OAuthProtocol.stringify_keys(client)["clientId"],
            redirect_uri: body["redirect_uri"],
            code_verifier: body["code_verifier"]
          )
          OAuthProtocol.issue_tokens(
            ctx,
            config[:store],
            model: "oauthAccessToken",
            client: client,
            session: code[:session],
            scopes: code[:scopes],
            include_refresh: code[:scopes].include?("offline_access"),
            issuer: validate_issuer_url(OAuthProtocol.issuer(ctx)),
            prefix: config[:prefix],
            refresh_token_expires_in: config[:refresh_token_expires_in],
            access_token_expires_in: config[:access_token_expires_in],
            audience: audience,
            grant_type: OAuthProtocol::AUTH_CODE_GRANT,
            jwt_access_token: !audience.nil?,
            nonce: code[:nonce],
            auth_time: code[:auth_time],
            reference_id: code[:reference_id],
            filter_id_token_claims_by_scope: true
          )
        when OAuthProtocol::REFRESH_GRANT
          OAuthProtocol.refresh_tokens(
            ctx,
            config[:store],
            model: "oauthAccessToken",
            client: client,
            refresh_token: body["refresh_token"],
            scopes: body["scope"],
            issuer: validate_issuer_url(OAuthProtocol.issuer(ctx)),
            prefix: config[:prefix],
            refresh_token_expires_in: config[:refresh_token_expires_in],
            access_token_expires_in: config[:access_token_expires_in],
            audience: audience,
            jwt_access_token: !audience.nil?,
            filter_id_token_claims_by_scope: true
          )
        else
          raise APIError.new("BAD_REQUEST", message: "unsupported_grant_type")
        end
      end

      def validate_resource!(config, body)
        resources = Array(body["resource"]).compact.map(&:to_s)
        return nil if resources.empty?

        valid = Array(config[:valid_audiences]).map(&:to_s)
        resources.each do |resource|
          raise APIError.new("BAD_REQUEST", message: "requested resource invalid") unless valid.empty? || valid.include?(resource)
        end
        (resources.length == 1) ? resources.first : resources
      end

      def introspect(ctx, config)
        OAuthProtocol.authenticate_client!(ctx, "oauthClient", store_client_secret: config[:store_client_secret], prefix: config[:prefix])
        body = OAuthProtocol.stringify_keys(ctx.body)
        token_record = OAuthProtocol.find_token_by_hint(config[:store], body["token"].to_s, body["token_type_hint"], prefix: config[:prefix])
        return inactive_token_response if token_record.nil? || token_record["revoked"] || (token_record["expiresAt"] && token_record["expiresAt"] <= Time.now)

        {
          active: true,
          client_id: token_record["clientId"],
          scope: OAuthProtocol.scope_string(token_record["scope"] || token_record["scopes"]),
          sub: token_record["subject"] || token_record.dig("user", "id"),
          iss: token_record["issuer"],
          iat: token_record["issuedAt"]&.to_i,
          exp: token_record["expiresAt"]&.to_i,
          sid: token_record["sessionId"],
          aud: token_record["audience"]
        }.compact
      end

      def revoke(ctx, config)
        OAuthProtocol.authenticate_client!(ctx, "oauthClient", store_client_secret: config[:store_client_secret], prefix: config[:prefix])
        body = OAuthProtocol.stringify_keys(ctx.body)
        if (token_record = OAuthProtocol.find_token_by_hint(config[:store], body["token"].to_s, body["token_type_hint"], prefix: config[:prefix]))
          token_record["revoked"] = Time.now
        end
        {revoked: true}
      end

      def inactive_token_response
        {active: false}
      end
    end
  end
end
