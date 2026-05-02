# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_token_endpoint(config)
      Endpoint.new(path: "/oauth2/token", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.authenticate_client!(ctx, "oauthClient", store_client_secret: config[:store_client_secret], prefix: config[:prefix])
        client_grants = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(client)["grantTypes"])
        if client_grants.any? && !client_grants.include?(body["grant_type"].to_s)
          raise APIError.new("BAD_REQUEST", message: "unsupported_grant_type")
        end
        audience = oauth_validate_resource!(ctx, config, body)

        response = case body["grant_type"]
        when OAuthProtocol::AUTH_CODE_GRANT
          code = OAuthProtocol.consume_code!(
            config[:store],
            body["code"],
            client_id: body["client_id"],
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
            include_refresh: code[:scopes].include?("offline_access") || OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(client)["grantTypes"]).include?(OAuthProtocol::REFRESH_GRANT),
            issuer: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)),
            prefix: config[:prefix],
            refresh_token_expires_in: config[:refresh_token_expires_in],
            access_token_expires_in: oauth_access_token_expires_in(config, code[:scopes], machine: false),
            audience: audience,
            grant_type: OAuthProtocol::AUTH_CODE_GRANT,
            custom_token_response_fields: config[:custom_token_response_fields],
            custom_access_token_claims: config[:custom_access_token_claims],
            custom_id_token_claims: config[:custom_id_token_claims],
            jwt_access_token: oauth_jwt_access_token?(config, audience),
            pairwise_secret: config[:pairwise_secret],
            nonce: code[:nonce],
            auth_time: code[:auth_time],
            reference_id: code[:reference_id],
            filter_id_token_claims_by_scope: true
          )
        when OAuthProtocol::CLIENT_CREDENTIALS_GRANT
          requested = OAuthProtocol.parse_scopes(body["scope"])
          allowed = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(client)["scopes"] || config[:scopes])
          requested = allowed if requested.empty?
          unless requested.all? { |scope| allowed.include?(scope) }
            raise APIError.new("BAD_REQUEST", message: "invalid_scope")
          end

          OAuthProtocol.issue_tokens(ctx, config[:store], model: "oauthAccessToken", client: client, session: {"user" => {}, "session" => {}}, scopes: requested, include_refresh: false, issuer: OAuthProtocol.issuer(ctx), prefix: config[:prefix], audience: audience, grant_type: OAuthProtocol::CLIENT_CREDENTIALS_GRANT, custom_token_response_fields: config[:custom_token_response_fields], custom_access_token_claims: config[:custom_access_token_claims], custom_id_token_claims: config[:custom_id_token_claims], jwt_access_token: oauth_jwt_access_token?(config, audience), pairwise_secret: config[:pairwise_secret], access_token_expires_in: oauth_access_token_expires_in(config, requested, machine: true), filter_id_token_claims_by_scope: true)
        when OAuthProtocol::REFRESH_GRANT
          refresh_record = OAuthProtocol.find_token_by_hint(config[:store], body["refresh_token"].to_s, "refresh_token", prefix: config[:prefix])
          refresh_scopes = OAuthProtocol.parse_scopes(body["scope"] || refresh_record&.fetch("scopes", nil))
          OAuthProtocol.refresh_tokens(ctx, config[:store], model: "oauthAccessToken", client: client, refresh_token: body["refresh_token"], scopes: body["scope"], issuer: OAuthProtocol.issuer(ctx), prefix: config[:prefix], refresh_token_expires_in: config[:refresh_token_expires_in], audience: audience, custom_token_response_fields: config[:custom_token_response_fields], custom_access_token_claims: config[:custom_access_token_claims], custom_id_token_claims: config[:custom_id_token_claims], jwt_access_token: oauth_jwt_access_token?(config, audience), pairwise_secret: config[:pairwise_secret], access_token_expires_in: oauth_access_token_expires_in(config, refresh_scopes, machine: false), filter_id_token_claims_by_scope: true)
        else
          raise APIError.new("BAD_REQUEST", message: "unsupported_grant_type")
        end
        ctx.json(response)
      end
    end

    def oauth_validate_resource!(ctx, config, body)
      resources = Array(body["resource"]).compact.map(&:to_s)
      return nil if resources.empty?

      valid = Array(config[:valid_audiences]).map(&:to_s)
      return (resources.length == 1) ? resources.first : resources if valid.empty?

      resources.each do |resource|
        raise APIError.new("BAD_REQUEST", message: "requested resource invalid") unless valid.include?(resource)
      end
      (resources.length == 1) ? resources.first : resources
    end

    def oauth_access_token_expires_in(config, scopes, machine:)
      base = machine ? config[:m2m_access_token_expires_in] : config[:access_token_expires_in]
      expirations = normalize_hash(config[:scope_expirations] || {})
      matches = OAuthProtocol.parse_scopes(scopes).filter_map do |scope|
        value = expirations[scope.to_sym] || expirations[scope]
        oauth_duration_seconds(value) if value
      end
      ([base.to_i] + matches).compact.min
    end

    def oauth_duration_seconds(value)
      return value.to_i if value.is_a?(Numeric)

      match = value.to_s.match(/\A(\d+)([smhd])?\z/)
      return value.to_i unless match

      amount = match[1].to_i
      case match[2]
      when "m" then amount * 60
      when "h" then amount * 3600
      when "d" then amount * 86_400
      else amount
      end
    end
  end
end
