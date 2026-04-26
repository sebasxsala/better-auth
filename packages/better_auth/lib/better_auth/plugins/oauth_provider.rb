# frozen_string_literal: true

module BetterAuth
  module Plugins
    module OAuthProvider
      module_function

      def validate_issuer_url(value)
        uri = URI.parse(value.to_s)
        uri.query = nil
        uri.fragment = nil
        if uri.scheme == "http" && !["localhost", "127.0.0.1"].include?(uri.host)
          uri.scheme = "https"
        end
        uri.to_s.sub(%r{/+\z}, "")
      rescue URI::InvalidURIError
        value.to_s.split(/[?#]/).first.sub(%r{/+\z}, "")
      end
    end

    module_function

    def oauth_provider(options = {})
      config = {
        scopes: [],
        grant_types: [OAuthProtocol::AUTH_CODE_GRANT, OAuthProtocol::CLIENT_CREDENTIALS_GRANT, OAuthProtocol::REFRESH_GRANT],
        store: OAuthProtocol.stores
      }.merge(normalize_hash(options))

      Plugin.new(
        id: "oauth-provider",
        endpoints: oauth_provider_endpoints(config),
        schema: oauth_provider_schema,
        options: config
      )
    end

    def oauth_provider_endpoints(config)
      {
        get_o_auth_server_config: oauth_server_metadata_endpoint(config),
        get_open_id_config: oauth_openid_metadata_endpoint(config),
        register_o_auth_client: oauth_register_client_endpoint(config),
        get_o_auth_client: oauth_get_client_endpoint(config),
        get_o_auth_client_public: oauth_get_client_public_endpoint(config),
        list_o_auth_clients: oauth_list_clients_endpoint,
        delete_o_auth_client: oauth_delete_client_endpoint,
        o_auth2_token: oauth_token_endpoint(config),
        o_auth2_introspect: oauth_introspect_endpoint(config),
        o_auth2_revoke: oauth_revoke_endpoint(config),
        o_auth2_user_info: oauth_userinfo_endpoint(config)
      }
    end

    def oauth_server_metadata_endpoint(config)
      Endpoint.new(path: "/.well-known/oauth-authorization-server", method: "GET", metadata: {hide: true}) do |ctx|
        base = OAuthProtocol.endpoint_base(ctx)
        ctx.json({
          issuer: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)),
          authorization_endpoint: "#{base}/oauth2/authorize",
          token_endpoint: "#{base}/oauth2/token",
          jwks_uri: "#{base}/jwks",
          registration_endpoint: "#{base}/oauth2/register",
          introspection_endpoint: "#{base}/oauth2/introspect",
          revocation_endpoint: "#{base}/oauth2/revoke",
          response_types_supported: ["code"],
          response_modes_supported: ["query"],
          grant_types_supported: config[:grant_types],
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: true,
          scopes_supported: config[:scopes]
        })
      end
    end

    def oauth_openid_metadata_endpoint(config)
      Endpoint.new(path: "/.well-known/openid-configuration", method: "GET", metadata: {hide: true}) do |ctx|
        base = OAuthProtocol.endpoint_base(ctx)
        ctx.json({
          issuer: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)),
          authorization_endpoint: "#{base}/oauth2/authorize",
          token_endpoint: "#{base}/oauth2/token",
          jwks_uri: "#{base}/jwks",
          registration_endpoint: "#{base}/oauth2/register",
          introspection_endpoint: "#{base}/oauth2/introspect",
          revocation_endpoint: "#{base}/oauth2/revoke",
          response_types_supported: ["code"],
          response_modes_supported: ["query"],
          grant_types_supported: config[:grant_types],
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: true,
          scopes_supported: config[:scopes],
          userinfo_endpoint: "#{base}/oauth2/userinfo",
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["HS256"],
          end_session_endpoint: "#{base}/oauth2/end-session",
          acr_values_supported: ["urn:mace:incommon:iap:bronze"],
          prompt_values_supported: ["login", "consent", "create", "select_account"],
          claims_supported: config[:claims] || []
        })
      end
    end

    def oauth_register_client_endpoint(_config)
      Endpoint.new(path: "/oauth2/register", method: "POST") do |ctx|
        session = Routes.current_session(ctx, allow_nil: true)
        body = OAuthProtocol.stringify_keys(ctx.body)
        public_request = body["token_endpoint_auth_method"] == "none"
        raise APIError.new("UNAUTHORIZED") unless session || public_request

        ctx.json(OAuthProtocol.create_client(ctx, model: "oauthClient", body: body, owner_session: session))
      end
    end

    def oauth_get_client_endpoint(_config)
      Endpoint.new(path: "/oauth2/client/:id", method: "GET") do |ctx|
        Routes.current_session(ctx)
        client = OAuthProtocol.find_client(ctx, "oauthClient", ctx.params["id"] || ctx.params[:id])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client

        ctx.json(OAuthProtocol.client_response(client, include_secret: false))
      end
    end

    def oauth_get_client_public_endpoint(_config)
      Endpoint.new(path: "/oauth2/client", method: "GET") do |ctx|
        query = OAuthProtocol.stringify_keys(ctx.query)
        client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client

        ctx.json(OAuthProtocol.client_response(client, include_secret: false))
      end
    end

    def oauth_list_clients_endpoint
      Endpoint.new(path: "/oauth2/clients", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        clients = ctx.context.adapter.find_many(model: "oauthClient", where: [{field: "userId", value: session[:user]["id"]}])
        ctx.json(clients.map { |client| OAuthProtocol.client_response(client, include_secret: false) })
      end
    end

    def oauth_delete_client_endpoint
      Endpoint.new(path: "/oauth2/client", method: "DELETE") do |ctx|
        Routes.current_session(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        ctx.context.adapter.delete(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}])
        ctx.json({status: true})
      end
    end

    def oauth_token_endpoint(config)
      Endpoint.new(path: "/oauth2/token", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.authenticate_client!(ctx, "oauthClient")
        response = case body["grant_type"]
        when OAuthProtocol::CLIENT_CREDENTIALS_GRANT
          requested = OAuthProtocol.parse_scopes(body["scope"])
          allowed = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(client)["scopes"] || config[:scopes])
          unless requested.all? { |scope| allowed.include?(scope) }
            raise APIError.new("BAD_REQUEST", message: "invalid_scope")
          end

          OAuthProtocol.issue_tokens(ctx, config[:store], model: "oauthAccessToken", client: client, session: {"user" => {}, "session" => {}}, scopes: requested, include_refresh: false, issuer: OAuthProtocol.issuer(ctx))
        when OAuthProtocol::REFRESH_GRANT
          OAuthProtocol.refresh_tokens(ctx, config[:store], model: "oauthAccessToken", client: client, refresh_token: body["refresh_token"], scopes: body["scope"], issuer: OAuthProtocol.issuer(ctx))
        else
          raise APIError.new("BAD_REQUEST", message: "unsupported_grant_type")
        end
        ctx.json(response)
      end
    end

    def oauth_introspect_endpoint(config)
      Endpoint.new(path: "/oauth2/introspect", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        OAuthProtocol.authenticate_client!(ctx, "oauthClient")
        body = OAuthProtocol.stringify_keys(ctx.body)
        token = config[:store][:tokens][body["token"].to_s] || config[:store][:refresh_tokens][body["token"].to_s]
        active = token && !token["revoked"] && (!token["expiresAt"] || token["expiresAt"] > Time.now)
        ctx.json(active ? {
          active: true,
          client_id: token["clientId"],
          scope: OAuthProtocol.scope_string(token["scope"] || token["scopes"]),
          sub: token.dig("user", "id"),
          exp: token["expiresAt"]&.to_i
        } : {active: false})
      end
    end

    def oauth_revoke_endpoint(config)
      Endpoint.new(path: "/oauth2/revoke", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        OAuthProtocol.authenticate_client!(ctx, "oauthClient")
        body = OAuthProtocol.stringify_keys(ctx.body)
        if (token = config[:store][:tokens][body["token"].to_s] || config[:store][:refresh_tokens][body["token"].to_s])
          token["revoked"] = Time.now
        end
        ctx.json({revoked: true})
      end
    end

    def oauth_userinfo_endpoint(config)
      Endpoint.new(path: "/oauth2/userinfo", method: "GET") do |ctx|
        ctx.json(OAuthProtocol.userinfo(config[:store], ctx.headers["authorization"]))
      end
    end

    def oauth_provider_schema
      oidc_provider_schema.merge(
        oauthClient: {
          modelName: "oauthClient",
          fields: {
            clientId: {type: "string", unique: true, required: true},
            clientSecret: {type: "string", required: false},
            disabled: {type: "boolean", default_value: false, required: false},
            skipConsent: {type: "boolean", required: false},
            enableEndSession: {type: "boolean", required: false},
            scopes: {type: "string[]", required: false},
            userId: {type: "string", required: false},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }},
            updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }},
            name: {type: "string", required: false},
            uri: {type: "string", required: false},
            icon: {type: "string", required: false},
            contacts: {type: "string[]", required: false},
            tos: {type: "string", required: false},
            policy: {type: "string", required: false},
            softwareId: {type: "string", required: false},
            softwareVersion: {type: "string", required: false},
            softwareStatement: {type: "string", required: false},
            redirectUris: {type: "string[]", required: true},
            postLogoutRedirectUris: {type: "string[]", required: false},
            tokenEndpointAuthMethod: {type: "string", required: false},
            grantTypes: {type: "string[]", required: false},
            responseTypes: {type: "string[]", required: false},
            public: {type: "boolean", required: false},
            type: {type: "string", required: false},
            referenceId: {type: "string", required: false},
            metadata: {type: "json", required: false}
          }
        },
        oauthRefreshToken: {
          fields: {
            token: {type: "string", required: true},
            clientId: {type: "string", required: true},
            sessionId: {type: "string", required: false},
            userId: {type: "string", required: false},
            referenceId: {type: "string", required: false},
            expiresAt: {type: "date", required: false},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }},
            revoked: {type: "date", required: false},
            scopes: {type: "string[]", required: true}
          }
        }
      )
    end
  end
end
