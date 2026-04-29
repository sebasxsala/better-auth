# frozen_string_literal: true

require "jwt"

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
        allow_dynamic_client_registration: false,
        allow_unauthenticated_client_registration: false,
        client_registration_default_scopes: nil,
        client_registration_allowed_scopes: nil,
        signup: {},
        select_account: {},
        post_login: {},
        store_client_secret: "plain",
        prefix: {},
        refresh_token_expires_in: 2_592_000,
        store: OAuthProtocol.stores
      }.merge(normalize_hash(options))

      Plugin.new(
        id: "oauth-provider",
        endpoints: oauth_provider_endpoints(config),
        schema: oauth_provider_schema,
        rate_limit: oauth_provider_rate_limits(config),
        options: config
      )
    end

    def oauth_provider_endpoints(config)
      {
        get_o_auth_server_config: oauth_server_metadata_endpoint(config),
        get_open_id_config: oauth_openid_metadata_endpoint(config),
        register_o_auth_client: oauth_register_client_endpoint(config),
        create_o_auth_client: oauth_create_client_endpoint(config),
        admin_create_o_auth_client: oauth_create_client_endpoint(config),
        get_o_auth_client: oauth_get_client_endpoint(config),
        get_o_auth_client_public: oauth_get_client_public_endpoint(config),
        get_o_auth_client_public_prelogin: oauth_get_client_public_prelogin_endpoint(config),
        list_o_auth_clients: oauth_list_clients_endpoint(config),
        delete_o_auth_client: oauth_delete_client_endpoint(config),
        update_o_auth_client: oauth_update_client_endpoint(config),
        rotate_o_auth_client_secret: oauth_rotate_client_secret_endpoint(config),
        list_o_auth_consents: oauth_list_consents_endpoint,
        get_o_auth_consent: oauth_get_consent_endpoint,
        update_o_auth_consent: oauth_update_consent_endpoint,
        delete_o_auth_consent: oauth_delete_consent_endpoint,
        o_auth2_authorize: oauth_authorize_endpoint(config),
        o_auth2_continue: oauth_continue_endpoint(config),
        o_auth2_consent: oauth_consent_endpoint(config),
        o_auth2_token: oauth_token_endpoint(config),
        o_auth2_introspect: oauth_introspect_endpoint(config),
        o_auth2_revoke: oauth_revoke_endpoint(config),
        o_auth2_user_info: oauth_userinfo_endpoint(config),
        o_auth2_end_session: oauth_end_session_endpoint
      }
    end

    def oauth_server_metadata_endpoint(config)
      Endpoint.new(path: "/.well-known/oauth-authorization-server", method: "GET", metadata: {hide: true}) do |ctx|
        base = OAuthProtocol.endpoint_base(ctx)
        metadata = {
          issuer: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)),
          authorization_endpoint: "#{base}/oauth2/authorize",
          token_endpoint: "#{base}/oauth2/token",
          registration_endpoint: "#{base}/oauth2/register",
          introspection_endpoint: "#{base}/oauth2/introspect",
          revocation_endpoint: "#{base}/oauth2/revoke",
          response_types_supported: ["code"],
          response_modes_supported: ["query"],
          grant_types_supported: config[:grant_types],
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
          introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: true,
          scopes_supported: config.dig(:advertised_metadata, :scopes_supported) || config[:scopes]
        }
        metadata[:jwks_uri] = oauth_jwks_uri(config) if oauth_jwks_uri(config)
        ctx.json(metadata, headers: oauth_metadata_headers)
      end
    end

    def oauth_openid_metadata_endpoint(config)
      Endpoint.new(path: "/.well-known/openid-configuration", method: "GET", metadata: {hide: true}) do |ctx|
        unless OAuthProtocol.parse_scopes(config[:scopes]).include?("openid")
          raise APIError.new("NOT_FOUND", message: "openid is not enabled")
        end

        base = OAuthProtocol.endpoint_base(ctx)
        metadata = {
          issuer: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)),
          authorization_endpoint: "#{base}/oauth2/authorize",
          token_endpoint: "#{base}/oauth2/token",
          registration_endpoint: "#{base}/oauth2/register",
          introspection_endpoint: "#{base}/oauth2/introspect",
          revocation_endpoint: "#{base}/oauth2/revoke",
          response_types_supported: ["code"],
          response_modes_supported: ["query"],
          grant_types_supported: config[:grant_types],
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
          introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: true,
          scopes_supported: config.dig(:advertised_metadata, :scopes_supported) || config[:scopes],
          userinfo_endpoint: "#{base}/oauth2/userinfo",
          subject_types_supported: config[:pairwise_secret] ? ["public", "pairwise"] : ["public"],
          id_token_signing_alg_values_supported: ["HS256"],
          end_session_endpoint: "#{base}/oauth2/end-session",
          acr_values_supported: ["urn:mace:incommon:iap:bronze"],
          prompt_values_supported: ["login", "consent", "create", "select_account"],
          claims_supported: config.dig(:advertised_metadata, :claims_supported) || config[:claims] || []
        }
        metadata[:jwks_uri] = oauth_jwks_uri(config) if oauth_jwks_uri(config)
        ctx.json(metadata, headers: oauth_metadata_headers)
      end
    end

    def oauth_register_client_endpoint(config)
      Endpoint.new(path: "/oauth2/register", method: "POST") do |ctx|
        session = Routes.current_session(ctx, allow_nil: true)
        body = OAuthProtocol.stringify_keys(ctx.body)
        unless config[:allow_dynamic_client_registration]
          raise APIError.new("FORBIDDEN", message: "Client registration is disabled")
        end
        unless session || config[:allow_unauthenticated_client_registration]
          raise APIError.new("UNAUTHORIZED")
        end
        if body.key?("skip_consent") || body.key?("skipConsent")
          raise APIError.new("BAD_REQUEST", message: "skip_consent is not allowed during dynamic client registration")
        end

        client = OAuthProtocol.create_client(
          ctx,
          model: "oauthClient",
          body: body,
          owner_session: session,
          unauthenticated: session.nil?,
          default_scopes: config[:client_registration_default_scopes] || config[:scopes],
          allowed_scopes: config[:client_registration_allowed_scopes] || config[:scopes],
          store_client_secret: config[:store_client_secret],
          prefix: config[:prefix],
          dynamic_registration: true
        )
        ctx.json(client, status: 201, headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"})
      end
    end

    def oauth_create_client_endpoint(config)
      Endpoint.new(path: "/oauth2/create-client", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "create")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.create_client(
          ctx,
          model: "oauthClient",
          body: body,
          owner_session: session,
          default_scopes: config[:client_registration_default_scopes] || config[:scopes],
          allowed_scopes: config[:client_registration_allowed_scopes] || config[:scopes],
          store_client_secret: config[:store_client_secret],
          prefix: config[:prefix],
          dynamic_registration: false
        )
        ctx.json(client, status: 201, headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"})
      end
    end

    def oauth_get_client_endpoint(config)
      Endpoint.new(path: "/oauth2/client/:id", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "read")
        client = OAuthProtocol.find_client(ctx, "oauthClient", ctx.params["id"] || ctx.params[:id])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session)

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

    def oauth_get_client_public_prelogin_endpoint(_config)
      Endpoint.new(path: "/oauth2/public-client-prelogin", method: "GET") do |ctx|
        query = OAuthProtocol.stringify_keys(ctx.query)
        client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        raise APIError.new("NOT_FOUND", message: "client not found") if OAuthProtocol.stringify_keys(client)["disabled"]

        ctx.json(oauth_public_client_response(client))
      end
    end

    def oauth_list_clients_endpoint(config)
      Endpoint.new(path: "/oauth2/clients", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "list")
        clients = ctx.context.adapter.find_many(model: "oauthClient", where: [{field: "userId", value: session[:user]["id"]}])
        ctx.json(clients.map { |client| OAuthProtocol.client_response(client, include_secret: false) })
      end
    end

    def oauth_delete_client_endpoint(config)
      Endpoint.new(path: "/oauth2/client", method: "DELETE") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "delete")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session)
        ctx.context.adapter.delete(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}])
        ctx.json({status: true})
      end
    end

    def oauth_update_client_endpoint(config)
      Endpoint.new(path: "/oauth2/client", method: "PATCH") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "update")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session)

        update_source = OAuthProtocol.stringify_keys(body["update"] || body)
        update = oauth_client_update_data(update_source)
        updated = update.empty? ? client : ctx.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}], update: update.merge(updatedAt: Time.now))
        ctx.json(OAuthProtocol.client_response(updated, include_secret: false))
      end
    end

    def oauth_rotate_client_secret_endpoint(config)
      Endpoint.new(path: "/oauth2/client/rotate-secret", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "rotate")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session)
        client_data = OAuthProtocol.stringify_keys(client)
        raise APIError.new("BAD_REQUEST", message: "public clients cannot rotate secrets") if client_data["public"] || client_data["tokenEndpointAuthMethod"] == "none"

        client_secret = Crypto.random_string(32)
        updated = ctx.context.adapter.update(
          model: "oauthClient",
          where: [{field: "clientId", value: body["client_id"]}],
          update: {clientSecret: OAuthProtocol.store_client_secret_value(ctx, client_secret, config[:store_client_secret]), updatedAt: Time.now}
        )
        response = OAuthProtocol.client_response(updated, include_secret: false)
        ctx.json(response.merge(client_secret: OAuthProtocol.apply_prefix(client_secret, config[:prefix], :client_secret)))
      end
    end

    def oauth_list_consents_endpoint
      Endpoint.new(path: "/oauth2/consents", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        consents = ctx.context.adapter.find_many(model: "oauthConsent", where: [{field: "userId", value: session[:user]["id"]}])
        ctx.json(consents.map { |consent| oauth_consent_response(consent) })
      end
    end

    def oauth_get_consent_endpoint
      Endpoint.new(path: "/oauth2/consent", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        query = OAuthProtocol.stringify_keys(ctx.query)
        consent = oauth_find_user_consent(ctx, session, query["client_id"])
        raise APIError.new("NOT_FOUND", message: "consent not found") unless consent

        ctx.json(oauth_consent_response(consent))
      end
    end

    def oauth_update_consent_endpoint
      Endpoint.new(path: "/oauth2/consent", method: "PATCH") do |ctx|
        session = Routes.current_session(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        consent = oauth_find_user_consent(ctx, session, body["client_id"])
        raise APIError.new("NOT_FOUND", message: "consent not found") unless consent

        scopes = OAuthProtocol.parse_scopes(body["scope"] || body["scopes"])
        existing = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(consent)["scopes"])
        unless scopes.all? { |scope| existing.include?(scope) }
          raise APIError.new("BAD_REQUEST", message: "invalid_scope")
        end

        updated = ctx.context.adapter.update(
          model: "oauthConsent",
          where: [{field: "id", value: OAuthProtocol.stringify_keys(consent)["id"]}],
          update: {scopes: scopes, consentGiven: true, updatedAt: Time.now}
        )
        ctx.json(oauth_consent_response(updated))
      end
    end

    def oauth_delete_consent_endpoint
      Endpoint.new(path: "/oauth2/consent", method: "DELETE") do |ctx|
        session = Routes.current_session(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        consent = oauth_find_user_consent(ctx, session, body["client_id"])
        raise APIError.new("NOT_FOUND", message: "consent not found") unless consent

        ctx.context.adapter.delete(model: "oauthConsent", where: [{field: "id", value: OAuthProtocol.stringify_keys(consent)["id"]}])
        ctx.json({deleted: true})
      end
    end

    def oauth_authorize_endpoint(config)
      Endpoint.new(path: "/oauth2/authorize", method: "GET") do |ctx|
        oauth_authorize_flow(ctx, config, OAuthProtocol.stringify_keys(ctx.query))
      end
    end

    def oauth_continue_endpoint(config)
      Endpoint.new(path: "/oauth2/continue", method: "POST") do |ctx|
        Routes.current_session(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        action = if body["selected"] == true
          "select_account"
        elsif body["created"] == true
          "create"
        elsif body["postLogin"] == true || body["post_login"] == true
          "post_login"
        end
        raise APIError.new("BAD_REQUEST", message: "Missing parameters") unless action

        query = oauth_verified_query!(ctx, body["oauth_query"])
        oauth_delete_prompt!(query, action) unless action == "post_login"
        url = oauth_redirect_location { oauth_authorize_flow(ctx, config, query, continue_post_login: action == "post_login") }
        ctx.json({redirect: true, url: url})
      end
    end

    def oauth_authorize_flow(ctx, config, query, continue_post_login: false)
      response_type = query["response_type"].to_s

      client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
      raise APIError.new("BAD_REQUEST", message: "invalid_client") unless client
      OAuthProtocol.validate_redirect_uri!(client, query["redirect_uri"])
      if response_type != "code"
        raise ctx.redirect(oauth_authorize_error_redirect(ctx, query, "unsupported_response_type", "response_type must be code"))
      end

      scopes = OAuthProtocol.parse_scopes(query["scope"])
      scopes = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(client)["scopes"] || config[:scopes]) if scopes.empty?
      prompts = OAuthProtocol.parse_scopes(query["prompt"])
      client_data = OAuthProtocol.stringify_keys(client)
      if client_data["disabled"]
        raise ctx.redirect(oauth_authorize_error_redirect(ctx, query, "invalid_client", "client is disabled"))
      end
      allowed_scopes = OAuthProtocol.parse_scopes(client_data["scopes"])
      allowed_scopes = OAuthProtocol.parse_scopes(config[:scopes]) if allowed_scopes.empty?
      unless scopes.all? { |scope| allowed_scopes.include?(scope) }
        raise ctx.redirect(oauth_authorize_error_redirect(ctx, query, "invalid_scope", "invalid scope"))
      end
      pkce_error = OAuthProtocol.validate_authorize_pkce(client_data, scopes, query["code_challenge"], query["code_challenge_method"])
      raise ctx.redirect(oauth_authorize_error_redirect(ctx, query, "invalid_request", pkce_error)) if pkce_error

      session = Routes.current_session(ctx, allow_nil: true)
      unless session
        if prompts.include?("none")
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "login_required", state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))))
        end

        if prompts.include?("create")
          raise ctx.redirect(oauth_prompt_redirect(ctx, config, query, "create"))
        end

        raise ctx.redirect(oauth_prompt_redirect(ctx, config, query, "login"))
      end

      if prompts.include?("select_account") && !continue_post_login
        if prompts.include?("none")
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "account_selection_required", state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))))
        end

        raise ctx.redirect(oauth_prompt_redirect(ctx, config, query, "select_account"))
      end

      if config.dig(:post_login, :should_redirect).respond_to?(:call) && !continue_post_login
        should_redirect = config.dig(:post_login, :should_redirect).call({user: session[:user], session: session[:session], client: client_data, scopes: scopes})
        if should_redirect
          if prompts.include?("none")
            raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "interaction_required", state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))))
          end

          raise ctx.redirect(oauth_prompt_redirect(ctx, config, query, "post_login", page: should_redirect.is_a?(String) ? should_redirect : nil))
        end
      end

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

    def oauth_prompt_redirect(ctx, config, query, type, page: nil)
      target = page || oauth_prompt_page(config, type)

      "#{target}?#{oauth_signed_query(ctx, query)}"
    end

    def oauth_prompt_page(config, type)
      case type
      when "create"
        config.dig(:signup, :page) || config[:login_page]
      when "select_account"
        config.dig(:select_account, :page) || config[:login_page]
      when "post_login"
        config.dig(:post_login, :page) || config[:login_page]
      when "consent"
        config[:consent_page]
      else
        config[:login_page]
      end
    end

    def oauth_signed_query(ctx, query)
      data = OAuthProtocol.stringify_keys(query).compact
      data["exp"] = (Time.now.to_i + 600).to_s
      unsigned = URI.encode_www_form(data)
      signature = Crypto.hmac_signature(unsigned, ctx.context.secret, encoding: :base64url)
      "#{unsigned}&#{URI.encode_www_form("sig" => signature)}"
    end

    def oauth_verified_query!(ctx, oauth_query)
      raise APIError.new("BAD_REQUEST", message: "missing oauth query") if oauth_query.to_s.empty?

      pairs = URI.decode_www_form(oauth_query.to_s)
      signature = pairs.reverse_each.find { |key, _value| key == "sig" }&.last
      unsigned_pairs = pairs.filter_map { |key, value| [key, value] unless key == "sig" }
      unsigned = URI.encode_www_form(unsigned_pairs)
      exp = unsigned_pairs.reverse_each.find { |key, _value| key == "exp" }&.last.to_i
      unless signature && exp >= Time.now.to_i && Crypto.verify_hmac_signature(unsigned, signature, ctx.context.secret, encoding: :base64url)
        raise APIError.new("BAD_REQUEST", message: "invalid oauth query")
      end

      unsigned_pairs.each_with_object({}) do |(key, value), result|
        next if key == "exp"

        result[key] = if result.key?(key)
          Array(result[key]) << value
        else
          value
        end
      end
    end

    def oauth_delete_prompt!(query, prompt)
      prompts = OAuthProtocol.parse_scopes(query["prompt"])
      prompts.delete(prompt)
      if prompts.empty?
        query.delete("prompt")
      else
        query["prompt"] = OAuthProtocol.scope_string(prompts)
      end
    end

    def oauth_redirect_location
      yield
    rescue APIError => error
      location = error.headers["location"]
      return location if location

      raise
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

        granted_scopes = OAuthProtocol.parse_scopes(body["scope"] || body["scopes"])
        granted_scopes = consent[:scopes] if granted_scopes.empty?
        unless granted_scopes.all? { |scope| consent[:scopes].include?(scope) }
          raise APIError.new("BAD_REQUEST", message: "invalid_scope")
        end

        oauth_store_consent(ctx, consent[:client], consent[:session], granted_scopes)
        redirect = oauth_authorization_redirect(ctx, config, query, consent[:session], consent[:client], granted_scopes)
        ctx.json({redirectURI: redirect})
      end
    end

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
            audience: audience,
            grant_type: OAuthProtocol::AUTH_CODE_GRANT,
            custom_token_response_fields: config[:custom_token_response_fields],
            custom_access_token_claims: config[:custom_access_token_claims],
            jwt_access_token: oauth_jwt_access_token?(config, audience),
            pairwise_secret: config[:pairwise_secret],
            nonce: code[:nonce],
            auth_time: code[:auth_time],
            reference_id: code[:reference_id]
          )
        when OAuthProtocol::CLIENT_CREDENTIALS_GRANT
          requested = OAuthProtocol.parse_scopes(body["scope"])
          allowed = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(client)["scopes"] || config[:scopes])
          unless requested.all? { |scope| allowed.include?(scope) }
            raise APIError.new("BAD_REQUEST", message: "invalid_scope")
          end

          OAuthProtocol.issue_tokens(ctx, config[:store], model: "oauthAccessToken", client: client, session: {"user" => {}, "session" => {}}, scopes: requested, include_refresh: false, issuer: OAuthProtocol.issuer(ctx), prefix: config[:prefix], audience: audience, grant_type: OAuthProtocol::CLIENT_CREDENTIALS_GRANT, custom_token_response_fields: config[:custom_token_response_fields], custom_access_token_claims: config[:custom_access_token_claims], jwt_access_token: oauth_jwt_access_token?(config, audience), pairwise_secret: config[:pairwise_secret])
        when OAuthProtocol::REFRESH_GRANT
          OAuthProtocol.refresh_tokens(ctx, config[:store], model: "oauthAccessToken", client: client, refresh_token: body["refresh_token"], scopes: body["scope"], issuer: OAuthProtocol.issuer(ctx), prefix: config[:prefix], refresh_token_expires_in: config[:refresh_token_expires_in], audience: audience, custom_token_response_fields: config[:custom_token_response_fields], custom_access_token_claims: config[:custom_access_token_claims], jwt_access_token: oauth_jwt_access_token?(config, audience), pairwise_secret: config[:pairwise_secret])
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
        code_challenge_method: query["code_challenge_method"],
        nonce: query["nonce"],
        reference_id: OAuthProtocol.stringify_keys(client)["referenceId"]
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
        client = OAuthProtocol.authenticate_client!(ctx, "oauthClient", store_client_secret: config[:store_client_secret], prefix: config[:prefix])
        body = OAuthProtocol.stringify_keys(ctx.body)
        token = OAuthProtocol.find_token_by_hint(config[:store], body["token"].to_s, body["token_type_hint"], prefix: config[:prefix])
        active = token && !token["revoked"] && (!token["expiresAt"] || token["expiresAt"] > Time.now)
        if active
          next ctx.json({
            active: true,
            client_id: token["clientId"],
            scope: OAuthProtocol.scope_string(token["scope"] || token["scopes"]),
            sub: token.dig("user", "id"),
            exp: token["expiresAt"]&.to_i
          })
        end

        jwt = oauth_introspect_jwt_access_token(ctx, client, body["token"].to_s)
        ctx.json(jwt || {active: false})
      end
    end

    def oauth_revoke_endpoint(config)
      Endpoint.new(path: "/oauth2/revoke", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        OAuthProtocol.authenticate_client!(ctx, "oauthClient", store_client_secret: config[:store_client_secret], prefix: config[:prefix])
        body = OAuthProtocol.stringify_keys(ctx.body)
        if (token = OAuthProtocol.find_token_by_hint(config[:store], body["token"].to_s, body["token_type_hint"], prefix: config[:prefix]))
          token["revoked"] = Time.now
        end
        ctx.json({revoked: true})
      end
    end

    def oauth_userinfo_endpoint(config)
      Endpoint.new(path: "/oauth2/userinfo", method: "GET") do |ctx|
        ctx.json(OAuthProtocol.userinfo(config[:store], ctx.headers["authorization"], additional_claim: config[:custom_user_info_claims] || config[:additional_claim], prefix: config[:prefix]))
      end
    end

    def oauth_end_session_endpoint
      Endpoint.new(path: "/oauth2/end-session", method: ["GET", "POST"], metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        input = OAuthProtocol.stringify_keys((ctx.method == "GET") ? ctx.query : ctx.body)
        id_token_hint = input["id_token_hint"].to_s
        raise APIError.new("UNAUTHORIZED", message: "invalid id token") if id_token_hint.empty?

        decoded = ::JWT.decode(id_token_hint, nil, false).first
        client_id = input["client_id"] || decoded["aud"]
        client = OAuthProtocol.find_client(ctx, "oauthClient", client_id)
        raise APIError.new("BAD_REQUEST", message: "invalid_client") unless client

        client_data = OAuthProtocol.stringify_keys(client)
        raise APIError.new("BAD_REQUEST", message: "invalid_client") if client_data["disabled"]
        raise APIError.new("UNAUTHORIZED", message: "client unable to logout") unless client_data["enableEndSession"]

        payload = Crypto.verify_jwt(id_token_hint, client_data["clientId"])
        raise APIError.new("UNAUTHORIZED", message: "invalid id token") unless payload
        raise APIError.new("BAD_REQUEST", message: "audience mismatch") if input["client_id"] && payload["aud"] != input["client_id"]

        if payload["sid"]
          ctx.context.adapter.delete(model: "session", where: [{field: "id", value: payload["sid"]}])
        end

        if input["post_logout_redirect_uri"]
          unless OAuthProtocol.client_logout_redirect_uris(client_data).include?(input["post_logout_redirect_uri"])
            raise APIError.new("BAD_REQUEST", message: "invalid post_logout_redirect_uri")
          end

          redirect = OAuthProtocol.redirect_uri_with_params(input["post_logout_redirect_uri"], state: input["state"])
          raise ctx.redirect(redirect)
        end

        ctx.json({status: true})
      rescue ::JWT::DecodeError
        raise APIError.new("UNAUTHORIZED", message: "invalid id token")
      end
    end

    def oauth_authorize_error_redirect(ctx, query, error, description)
      OAuthProtocol.redirect_uri_with_params(
        query["redirect_uri"],
        error: error,
        error_description: description,
        state: query["state"],
        iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx))
      )
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

    def oauth_assert_owned_client!(client, session)
      data = OAuthProtocol.stringify_keys(client)
      raise APIError.new("UNAUTHORIZED") unless data["userId"] && data["userId"] == session[:user]["id"]
    end

    def oauth_assert_client_privilege!(ctx, config, session, action)
      callback = config[:client_privileges]
      return unless callback.respond_to?(:call)

      allowed = callback.call({
        headers: ctx.headers,
        action: action,
        session: session[:session],
        user: session[:user]
      })
      raise APIError.new("UNAUTHORIZED") unless allowed
    end

    def oauth_client_update_data(source)
      update = {}
      update["name"] = source["client_name"] || source["name"] if source.key?("client_name") || source.key?("name")
      update["uri"] = source["client_uri"] if source.key?("client_uri")
      update["icon"] = source["logo_uri"] if source.key?("logo_uri")
      if source.key?("redirect_uris")
        redirects = Array(source["redirect_uris"]).map(&:to_s)
        update["redirectUris"] = redirects
        update["redirectUrls"] = redirects.join(",")
      end
      update["postLogoutRedirectUris"] = Array(source["post_logout_redirect_uris"]).map(&:to_s) if source.key?("post_logout_redirect_uris")
      update["grantTypes"] = Array(source["grant_types"]).map(&:to_s) if source.key?("grant_types")
      update["responseTypes"] = Array(source["response_types"]).map(&:to_s) if source.key?("response_types")
      update["scopes"] = OAuthProtocol.parse_scopes(source["scope"] || source["scopes"]) if source.key?("scope") || source.key?("scopes")
      update["enableEndSession"] = !!(source["enable_end_session"] || source["enableEndSession"]) if source.key?("enable_end_session") || source.key?("enableEndSession")
      update["metadata"] = source["metadata"] if source.key?("metadata")
      update
    end

    def oauth_find_user_consent(ctx, session, client_id)
      ctx.context.adapter.find_one(
        model: "oauthConsent",
        where: [
          {field: "clientId", value: client_id},
          {field: "userId", value: session[:user]["id"]}
        ]
      )
    end

    def oauth_consent_response(consent)
      data = OAuthProtocol.stringify_keys(consent)
      {
        id: data["id"],
        client_id: data["clientId"],
        user_id: data["userId"],
        scope: OAuthProtocol.scope_string(data["scopes"]),
        scopes: OAuthProtocol.parse_scopes(data["scopes"]),
        consent_given: !!data["consentGiven"]
      }.compact
    end

    def oauth_public_client_response(client)
      data = OAuthProtocol.stringify_keys(client)
      {
        client_id: data["clientId"],
        client_name: data["name"],
        client_uri: data["uri"],
        logo_uri: data["icon"],
        contacts: data["contacts"] || [],
        tos_uri: data["tos"],
        policy_uri: data["policy"]
      }.compact
    end

    def oauth_metadata_headers
      {"Cache-Control" => "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"}
    end

    def oauth_jwks_uri(config)
      config.dig(:advertised_metadata, :jwks_uri) ||
        config[:jwks_uri] ||
        config.dig(:jwks, :remote_url)
    end

    def oauth_validate_resource!(ctx, config, body)
      resources = Array(body["resource"]).compact.map(&:to_s)
      return nil if resources.empty?

      valid = Array(config[:valid_audiences] || [ctx.context.base_url]).map(&:to_s)
      resources.each do |resource|
        raise APIError.new("BAD_REQUEST", message: "requested resource invalid") unless valid.include?(resource)
      end
      (resources.length == 1) ? resources.first : resources
    end

    def oauth_provider_rate_limits(config)
      rate_limit = normalize_hash(config[:rate_limit] || {})
      [
        oauth_rate_limit_rule(rate_limit, :token, "/oauth2/token", window: 60, max: 20),
        oauth_rate_limit_rule(rate_limit, :authorize, "/oauth2/authorize", window: 60, max: 30),
        oauth_rate_limit_rule(rate_limit, :introspect, "/oauth2/introspect", window: 60, max: 100),
        oauth_rate_limit_rule(rate_limit, :revoke, "/oauth2/revoke", window: 60, max: 30),
        oauth_rate_limit_rule(rate_limit, :register, "/oauth2/register", window: 60, max: 5),
        oauth_rate_limit_rule(rate_limit, :userinfo, "/oauth2/userinfo", window: 60, max: 60)
      ].compact
    end

    def oauth_rate_limit_rule(rate_limit, key, path, window:, max:)
      override = rate_limit[key]
      return nil if override == false

      override = normalize_hash(override || {})
      {
        path_matcher: ->(request_path) { request_path == path },
        window: override[:window] || window,
        max: override[:max] || max
      }
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
            subjectType: {type: "string", required: false},
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
            authTime: {type: "date", required: false},
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
            authTime: {type: "date", required: false},
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
