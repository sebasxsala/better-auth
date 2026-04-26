# frozen_string_literal: true

module BetterAuth
  module Plugins
    module OIDCProvider
      VALID_PROMPTS = %w[none login consent create select_account].freeze

      module_function

      def parse_prompt(value)
        prompts = value.to_s.split(/\s+/).select { |prompt| VALID_PROMPTS.include?(prompt) }
        if prompts.include?("none") && prompts.length > 1
          raise APIError.new("BAD_REQUEST", message: "invalid_request")
        end

        prompts.to_set
      end
    end

    module_function

    def oidc_provider(options = {})
      config = {
        code_expires_in: 600,
        consent_page: "/oauth2/authorize",
        default_scope: "openid",
        access_token_expires_in: 3600,
        refresh_token_expires_in: 604_800,
        scopes: %w[openid profile email offline_access],
        store: OAuthProtocol.stores
      }.merge(normalize_hash(options))

      Plugin.new(
        id: "oidc-provider",
        endpoints: oidc_provider_endpoints(config),
        schema: oidc_provider_schema,
        options: config
      )
    end

    def oidc_provider_endpoints(config)
      {
        get_open_id_config: oidc_metadata_endpoint(config),
        o_auth2_authorize: oidc_authorize_endpoint(config),
        o_auth_consent: oidc_consent_endpoint(config),
        o_auth2_token: oidc_token_endpoint(config),
        o_auth2_user_info: oidc_userinfo_endpoint(config),
        register_o_auth_application: oidc_register_endpoint(config),
        get_o_auth_client: oidc_get_client_endpoint,
        end_session: oidc_end_session_endpoint
      }
    end

    def oidc_metadata_endpoint(config)
      Endpoint.new(path: "/.well-known/openid-configuration", method: "GET", metadata: {hide: true}) do |ctx|
        base = OAuthProtocol.endpoint_base(ctx)
        ctx.json({
          issuer: OAuthProtocol.issuer(ctx),
          authorization_endpoint: "#{base}/oauth2/authorize",
          token_endpoint: "#{base}/oauth2/token",
          userinfo_endpoint: "#{base}/oauth2/userinfo",
          jwks_uri: "#{base}/jwks",
          registration_endpoint: "#{base}/oauth2/register",
          end_session_endpoint: "#{base}/oauth2/endsession",
          scopes_supported: config[:scopes],
          response_types_supported: ["code"],
          response_modes_supported: ["query"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          acr_values_supported: ["urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["HS256", "none"],
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
          code_challenge_methods_supported: ["S256"],
          claims_supported: %w[sub iss aud exp nbf iat jti email email_verified name]
        }.merge(config[:metadata] || {}))
      end
    end

    def oidc_register_endpoint(config)
      Endpoint.new(path: "/oauth2/register", method: "POST") do |ctx|
        client = OAuthProtocol.create_client(ctx, model: "oauthApplication", body: ctx.body, default_auth_method: "client_secret_basic")
        ctx.json(client)
      end
    end

    def oidc_get_client_endpoint
      Endpoint.new(path: "/oauth2/client/:id", method: "GET") do |ctx|
        client = OAuthProtocol.find_client(ctx, "oauthApplication", ctx.params["id"] || ctx.params[:id])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client

        ctx.json(OAuthProtocol.client_response(client, include_secret: false))
      end
    end

    def oidc_authorize_endpoint(config)
      Endpoint.new(path: "/oauth2/authorize", method: "GET") do |ctx|
        query = OAuthProtocol.stringify_keys(ctx.query)
        prompts = OIDCProvider.parse_prompt(query["prompt"])
        session = Routes.current_session(ctx, allow_nil: true)
        if !session && prompts.include?("none")
          redirect = OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "login_required", state: query["state"], iss: OAuthProtocol.issuer(ctx))
          raise ctx.redirect(redirect)
        end
        raise APIError.new("UNAUTHORIZED") unless session

        client = OAuthProtocol.find_client(ctx, "oauthApplication", query["client_id"])
        raise APIError.new("BAD_REQUEST", message: "invalid_client") unless client
        OAuthProtocol.validate_redirect_uri!(client, query["redirect_uri"])

        scopes = OAuthProtocol.parse_scopes(query["scope"] || config[:default_scope])
        client_data = OAuthProtocol.stringify_keys(client)
        requires_consent = !client_data["skipConsent"] && (prompts.include?("consent") || !oauth_consent_granted?(ctx, client_data["clientId"], session[:user]["id"], scopes))
        if requires_consent
          if prompts.include?("none")
            redirect = OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "consent_required", state: query["state"], iss: OAuthProtocol.issuer(ctx))
            raise ctx.redirect(redirect)
          end

          consent_code = Crypto.random_string(32)
          config[:store][:consents][consent_code] = {
            query: query,
            session: session,
            client: client,
            scopes: scopes,
            expires_at: Time.now + config[:code_expires_in].to_i
          }
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(config[:consent_page], consent_code: consent_code, client_id: client_data["clientId"], scope: OAuthProtocol.scope_string(scopes)))
        end

        code = Crypto.random_string(32)
        OAuthProtocol.store_code(
          config[:store],
          code: code,
          client_id: query["client_id"],
          redirect_uri: query["redirect_uri"],
          session: session,
          scopes: scopes,
          code_challenge: query["code_challenge"],
          code_challenge_method: query["code_challenge_method"]
        )

        redirect = OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], code: code, state: query["state"], iss: OAuthProtocol.issuer(ctx))
        raise ctx.redirect(redirect)
      end
    end

    def oidc_consent_endpoint(config)
      Endpoint.new(path: "/oauth2/consent", method: "POST") do |ctx|
        Routes.current_session(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        consent = config[:store][:consents].delete(body["consent_code"].to_s)
        raise APIError.new("BAD_REQUEST", message: "invalid consent_code") unless consent
        raise APIError.new("BAD_REQUEST", message: "expired consent_code") if consent[:expires_at] <= Time.now

        query = consent[:query]
        if body["accept"] == false || body["accept"].to_s == "false"
          redirect = OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "access_denied", state: query["state"], iss: OAuthProtocol.issuer(ctx))
          next ctx.json({redirectURI: redirect})
        end

        oauth_store_consent(ctx, consent[:client], consent[:session], consent[:scopes])
        code = Crypto.random_string(32)
        OAuthProtocol.store_code(
          config[:store],
          code: code,
          client_id: query["client_id"],
          redirect_uri: query["redirect_uri"],
          session: consent[:session],
          scopes: consent[:scopes],
          code_challenge: query["code_challenge"],
          code_challenge_method: query["code_challenge_method"]
        )
        ctx.json({redirectURI: OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], code: code, state: query["state"], iss: OAuthProtocol.issuer(ctx))})
      end
    end

    def oidc_token_endpoint(config)
      Endpoint.new(path: "/oauth2/token", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = if body["client_id"]
          OAuthProtocol.find_client(ctx, "oauthApplication", body["client_id"])
        else
          OAuthProtocol.authenticate_client!(ctx, "oauthApplication")
        end
        raise APIError.new("UNAUTHORIZED", message: "invalid_client") unless client

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
            include_refresh: code[:scopes].include?("offline_access"),
            issuer: OAuthProtocol.issuer(ctx)
          )
        when OAuthProtocol::REFRESH_GRANT
          OAuthProtocol.refresh_tokens(ctx, config[:store], model: "oauthAccessToken", client: client, refresh_token: body["refresh_token"], scopes: body["scope"], issuer: OAuthProtocol.issuer(ctx))
        else
          raise APIError.new("BAD_REQUEST", message: "unsupported_grant_type")
        end
        ctx.json(response)
      end
    end

    def oidc_userinfo_endpoint(config)
      Endpoint.new(path: "/oauth2/userinfo", method: "GET") do |ctx|
        ctx.json(OAuthProtocol.userinfo(config[:store], ctx.headers["authorization"]))
      end
    end

    def oidc_end_session_endpoint
      Endpoint.new(path: "/oauth2/endsession", method: ["GET", "POST"], metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        input_source = (ctx.method == "GET") ? ctx.query : ctx.body
        input = OAuthProtocol.stringify_keys(input_source)
        if input["post_logout_redirect_uri"]
          client = OAuthProtocol.find_client(ctx, "oauthApplication", input["client_id"])
          raise APIError.new("BAD_REQUEST", message: "invalid_client") unless client
          unless OAuthProtocol.client_logout_redirect_uris(client).include?(input["post_logout_redirect_uri"])
            raise APIError.new("BAD_REQUEST", message: "invalid_request")
          end
        end

        Cookies.delete_session_cookie(ctx)
        redirect = input["post_logout_redirect_uri"] || "/"
        redirect = OAuthProtocol.redirect_uri_with_params(redirect, state: input["state"]) if input["state"]
        raise ctx.redirect(redirect)
      end
    end

    def oidc_provider_schema
      {
        oauthApplication: {
          modelName: "oauthApplication",
          fields: {
            name: {type: "string"},
            icon: {type: "string", required: false},
            uri: {type: "string", required: false},
            metadata: {type: "json", required: false},
            clientId: {type: "string", unique: true},
            clientSecret: {type: "string", required: false},
            redirectUrls: {type: "string"},
            redirectUris: {type: "string[]", required: false},
            postLogoutRedirectUris: {type: "string[]", required: false},
            tokenEndpointAuthMethod: {type: "string", required: false},
            skipConsent: {type: "boolean", required: false},
            grantTypes: {type: "string[]", required: false},
            responseTypes: {type: "string[]", required: false},
            scopes: {type: "string[]", required: false},
            type: {type: "string"},
            disabled: {type: "boolean", required: false, default_value: false},
            userId: {type: "string", required: false, references: {model: "users", field: "id", on_delete: "cascade"}, index: true},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }},
            updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }}
          }
        },
        oauthAccessToken: {
          modelName: "oauthAccessToken",
          fields: {
            accessToken: {type: "string", unique: true, required: false},
            token: {type: "string", unique: true, required: false},
            refreshToken: {type: "string", unique: true, required: false},
            accessTokenExpiresAt: {type: "date", required: false},
            expiresAt: {type: "date", required: false},
            clientId: {type: "string", required: true},
            userId: {type: "string", required: false},
            sessionId: {type: "string", required: false},
            scope: {type: "string", required: false},
            scopes: {type: "string[]", required: false},
            revoked: {type: "date", required: false},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }},
            updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }}
          }
        },
        oauthConsent: {
          modelName: "oauthConsent",
          fields: {
            clientId: {type: "string", required: true},
            userId: {type: "string", required: true},
            scopes: {type: "string[]", required: false},
            consentGiven: {type: "boolean", required: false},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }},
            updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }}
          }
        }
      }
    end
  end
end
