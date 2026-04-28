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

    remove_method :oauth_provider if method_defined?(:oauth_provider) || private_method_defined?(:oauth_provider)
    singleton_class.remove_method(:oauth_provider) if singleton_class.method_defined?(:oauth_provider) || singleton_class.private_method_defined?(:oauth_provider)

    def oauth_provider(options = {})
      config = {
        login_page: "/login",
        consent_page: "/oauth2/consent",
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
        o_auth2_authorize: oauth_authorize_endpoint(config),
        o_auth2_consent: oauth_consent_endpoint(config),
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

    def oauth_authorize_endpoint(config)
      Endpoint.new(path: "/oauth2/authorize", method: "GET") do |ctx|
        query = OAuthProtocol.stringify_keys(ctx.query)
        session = Routes.current_session(ctx, allow_nil: true)
        unless session
          if OAuthProtocol.parse_scopes(query["prompt"]).include?("none")
            raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "login_required", state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))))
          end

          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(config[:login_page], query))
        end

        client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
        raise APIError.new("BAD_REQUEST", message: "invalid_client") unless client
        OAuthProtocol.validate_redirect_uri!(client, query["redirect_uri"])

        scopes = OAuthProtocol.parse_scopes(query["scope"])
        scopes = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(client)["scopes"] || config[:scopes]) if scopes.empty?
        prompts = OAuthProtocol.parse_scopes(query["prompt"])
        client_data = OAuthProtocol.stringify_keys(client)
        requires_consent = !client_data["skipConsent"] && (prompts.include?("consent") || !oauth_consent_granted?(ctx, client_data["clientId"], session[:user]["id"], scopes))

        if requires_consent
          if prompts.include?("none")
            raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "consent_required", state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))))
          end

          consent_code = Crypto.random_string(32)
          config[:store][:consents][consent_code] = {
            query: query,
            session: session,
            client: client,
            scopes: scopes,
            expires_at: Time.now + 600
          }
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(config[:consent_page], consent_code: consent_code, client_id: client_data["clientId"], scope: OAuthProtocol.scope_string(scopes)))
        end

        oauth_redirect_with_code(ctx, config, query, session, client, scopes)
      end
    end

    def oauth_consent_endpoint(config)
      Endpoint.new(path: "/oauth2/consent", method: "POST") do |ctx|
        Routes.current_session(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        consent = config[:store][:consents].delete(body["consent_code"].to_s)
        raise APIError.new("BAD_REQUEST", message: "invalid consent_code") unless consent
        raise APIError.new("BAD_REQUEST", message: "expired consent_code") if consent[:expires_at] <= Time.now

        query = consent[:query]
        if body["accept"] == false || body["accept"].to_s == "false"
          redirect = OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "access_denied", state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)))
          next ctx.json({redirectURI: redirect})
        end

        oauth_store_consent(ctx, consent[:client], consent[:session], consent[:scopes])
        redirect = oauth_authorization_redirect(ctx, config, query, consent[:session], consent[:client], consent[:scopes])
        ctx.json({redirectURI: redirect})
      end
    end

    def oauth_token_endpoint(config)
      Endpoint.new(path: "/oauth2/token", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.authenticate_client!(ctx, "oauthClient")
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
            issuer: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))
          )
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

    def oauth_authorization_redirect(ctx, config, query, session, client, scopes)
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
      OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], code: code, state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)))
    end

    def oauth_redirect_with_code(ctx, config, query, session, client, scopes)
      raise ctx.redirect(oauth_authorization_redirect(ctx, config, query, session, client, scopes))
    end

    def oauth_consent_granted?(ctx, client_id, user_id, scopes)
      consent = ctx.context.adapter.find_one(
        model: "oauthConsent",
        where: [
          {field: "clientId", value: client_id},
          {field: "userId", value: user_id}
        ]
      )
      return false unless consent && consent["consentGiven"]

      granted = OAuthProtocol.parse_scopes(consent["scopes"])
      scopes.all? { |scope| granted.include?(scope) }
    end

    def oauth_store_consent(ctx, client, session, scopes)
      client_id = OAuthProtocol.stringify_keys(client)["clientId"]
      user_id = session[:user]["id"]
      existing = ctx.context.adapter.find_one(
        model: "oauthConsent",
        where: [
          {field: "clientId", value: client_id},
          {field: "userId", value: user_id}
        ]
      )
      data = {clientId: client_id, userId: user_id, scopes: scopes, consentGiven: true}
      if existing
        ctx.context.adapter.update(model: "oauthConsent", where: [{field: "id", value: existing.fetch("id")}], update: data)
      else
        ctx.context.adapter.create(model: "oauthConsent", data: data)
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
      {
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
            requirePKCE: {type: "boolean", required: false},
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
            referenceId: {type: "string", required: false},
            refreshId: {type: "string", required: false},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }},
            updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }}
          }
        },
        oauthConsent: {
          modelName: "oauthConsent",
          fields: {
            clientId: {type: "string", required: true},
            userId: {type: "string", required: false},
            referenceId: {type: "string", required: false},
            scopes: {type: "string[]", required: true},
            consentGiven: {type: "boolean", required: false},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }},
            updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }}
          }
        }
      }
    end
  end
end
