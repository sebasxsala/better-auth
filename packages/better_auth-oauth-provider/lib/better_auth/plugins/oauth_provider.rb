# frozen_string_literal: true

require "jwt"
require_relative "../oauth_provider/version"

module BetterAuth
  module Plugins
    module OAuthProvider
      module_function

      def validate_issuer_url(value)
        uri = URI.parse(value.to_s)
        uri.query = nil
        uri.fragment = nil
        if uri.scheme == "http" && !["localhost", "127.0.0.1", "::1"].include?(uri.hostname || uri.host)
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
        access_token_expires_in: 3600,
        m2m_access_token_expires_in: 3600,
        scope_expirations: {},
        store: OAuthProtocol.stores
      }.merge(normalize_hash(options))

      Plugin.new(
        id: "oauth-provider",
        version: BetterAuth::OAuthProvider::VERSION,
        init: oauth_provider_init(config),
        endpoints: oauth_provider_endpoints(config),
        schema: oauth_provider_schema,
        rate_limit: oauth_provider_rate_limits(config),
        options: config
      )
    end

    def oauth_provider_init(config)
      lambda do |context|
        advertised_scopes = Array(config.dig(:advertised_metadata, :scopes_supported)).map(&:to_s)
        provider_scopes = OAuthProtocol.parse_scopes(config[:scopes])
        missing_scopes = advertised_scopes - provider_scopes
        unless missing_scopes.empty?
          raise APIError.new("BAD_REQUEST", message: "advertised_metadata.scopes_supported #{missing_scopes.first} not found in scopes")
        end
        if config[:pairwise_secret] && config[:pairwise_secret].to_s.length < 32
          raise APIError.new("BAD_REQUEST", message: "pairwise_secret must be at least 32 characters")
        end
        if context.options.secondary_storage && !context.options.session[:store_session_in_database]
          raise APIError.new("BAD_REQUEST", message: "OAuth Provider requires session.store_session_in_database when using secondary storage")
        end
        nil
      end
    end

    def oauth_provider_endpoints(config)
      {
        get_o_auth_server_config: oauth_server_metadata_endpoint(config),
        get_open_id_config: oauth_openid_metadata_endpoint(config),
        register_o_auth_client: oauth_register_client_endpoint(config),
        create_o_auth_client: oauth_create_client_endpoint(config),
        admin_create_o_auth_client: oauth_admin_create_client_endpoint(config),
        admin_update_o_auth_client: oauth_admin_update_client_endpoint(config),
        get_o_auth_client: oauth_get_client_endpoint(config),
        get_o_auth_client_public: oauth_get_client_public_endpoint(config),
        get_o_auth_client_public_prelogin: oauth_get_client_public_prelogin_endpoint(config),
        get_o_auth_clients: oauth_list_clients_endpoint(config),
        list_o_auth_clients: oauth_list_clients_endpoint(config),
        delete_o_auth_client: oauth_delete_client_endpoint(config),
        update_o_auth_client: oauth_update_client_endpoint(config),
        rotate_o_auth_client_secret: oauth_rotate_client_secret_endpoint(config),
        get_o_auth_consents: oauth_list_consents_endpoint,
        list_o_auth_consents: oauth_list_consents_endpoint,
        get_o_auth_consent: oauth_get_consent_endpoint,
        update_o_auth_consent: oauth_update_consent_endpoint,
        delete_o_auth_consent: oauth_delete_consent_endpoint,
        legacy_get_o_auth_client: oauth_legacy_get_client_endpoint(config),
        legacy_get_o_auth_client_public: oauth_legacy_get_client_public_endpoint(config),
        legacy_list_o_auth_clients: oauth_legacy_list_clients_endpoint(config),
        legacy_update_o_auth_client: oauth_legacy_update_client_endpoint(config),
        legacy_delete_o_auth_client: oauth_legacy_delete_client_endpoint(config),
        legacy_list_o_auth_consents: oauth_legacy_list_consents_endpoint,
        legacy_get_o_auth_consent: oauth_legacy_get_consent_endpoint,
        legacy_update_o_auth_consent: oauth_legacy_update_consent_endpoint,
        legacy_delete_o_auth_consent: oauth_legacy_delete_consent_endpoint,
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
          token_endpoint_auth_methods_supported: oauth_token_auth_methods(config),
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
          id_token_signing_alg_values_supported: oauth_id_token_signing_algs(ctx, config),
          end_session_endpoint: "#{base}/oauth2/end-session",
          acr_values_supported: ["urn:mace:incommon:iap:bronze"],
          prompt_values_supported: oauth_prompt_values,
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
        body["require_pkce"] = true unless body.key?("require_pkce") || body.key?("requirePKCE")

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
          dynamic_registration: true,
          pairwise_secret: config[:pairwise_secret],
          strip_client_metadata: true,
          reference_id: oauth_client_reference(config, session)
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
          dynamic_registration: false,
          admin: false,
          pairwise_secret: config[:pairwise_secret],
          strip_client_metadata: true,
          reference_id: oauth_client_reference(config, session)
        )
        ctx.json(client, status: 201, headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"})
      end
    end

    def oauth_get_client_endpoint(config)
      Endpoint.new(path: "/oauth2/get-client", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "read")
        query = OAuthProtocol.stringify_keys(ctx.query)
        client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)

        ctx.json(OAuthProtocol.client_response(client, include_secret: false))
      end
    end

    def oauth_get_client_public_endpoint(_config)
      Endpoint.new(path: "/oauth2/public-client", method: "GET") do |ctx|
        Routes.current_session(ctx, allow_nil: true)
        query = OAuthProtocol.stringify_keys(ctx.query)
        client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        raise APIError.new("NOT_FOUND", message: "client not found") if OAuthProtocol.stringify_keys(client)["disabled"]

        ctx.json(oauth_public_client_response(client))
      end
    end

    def oauth_get_client_public_prelogin_endpoint(_config)
      Endpoint.new(path: "/oauth2/public-client-prelogin", method: "POST") do |ctx|
        input = OAuthProtocol.stringify_keys(ctx.body).merge(OAuthProtocol.stringify_keys(ctx.query))
        client = OAuthProtocol.find_client(ctx, "oauthClient", input["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        raise APIError.new("NOT_FOUND", message: "client not found") if OAuthProtocol.stringify_keys(client)["disabled"]

        ctx.json(oauth_public_client_response(client))
      end
    end

    def oauth_list_clients_endpoint(config)
      Endpoint.new(path: "/oauth2/get-clients", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "list")
        reference_id = config[:client_reference]&.call({user: session[:user], session: session[:session]})
        clients = if reference_id
          ctx.context.adapter.find_many(model: "oauthClient", where: [{field: "referenceId", value: reference_id}])
        else
          ctx.context.adapter.find_many(model: "oauthClient", where: [{field: "userId", value: session[:user]["id"]}])
        end
        ctx.json(clients.map { |client| OAuthProtocol.client_response(client, include_secret: false) })
      end
    end

    def oauth_delete_client_endpoint(config)
      Endpoint.new(path: "/oauth2/delete-client", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "delete")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)
        ctx.context.adapter.delete(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}])
        ctx.json({deleted: true})
      end
    end

    def oauth_update_client_endpoint(config)
      Endpoint.new(path: "/oauth2/update-client", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "update")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)

        update_source = OAuthProtocol.stringify_keys(body["update"] || {})
        update = oauth_client_update_data(update_source)
        updated = update.empty? ? client : ctx.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}], update: update.merge(updatedAt: Time.now))
        ctx.json(OAuthProtocol.client_response(updated, include_secret: false))
      end
    end

    def oauth_admin_create_client_endpoint(config)
      Endpoint.new(path: "/admin/oauth2/create-client", method: "POST", metadata: {server_only: true}) do |ctx|
        session = nil
        if config[:client_privileges].respond_to?(:call)
          session = Routes.current_session(ctx)
          oauth_assert_client_privilege!(ctx, config, session, "create")
        elsif config[:client_reference].respond_to?(:call)
          session = Routes.current_session(ctx, allow_nil: true)
        end
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.create_client(
          ctx,
          model: "oauthClient",
          body: body,
          owner_session: nil,
          default_scopes: config[:client_registration_default_scopes] || config[:scopes],
          allowed_scopes: config[:client_registration_allowed_scopes] || config[:scopes],
          store_client_secret: config[:store_client_secret],
          prefix: config[:prefix],
          dynamic_registration: false,
          admin: true,
          pairwise_secret: config[:pairwise_secret],
          strip_client_metadata: true,
          reference_id: oauth_client_reference(config, session)
        )
        ctx.json(client, status: 201, headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"})
      end
    end

    def oauth_admin_update_client_endpoint(_config)
      Endpoint.new(path: "/admin/oauth2/update-client", method: "PATCH", metadata: {server_only: true}) do |ctx|
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client

        update = oauth_client_update_data(OAuthProtocol.stringify_keys(body["update"] || {}), admin: true)
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
        oauth_assert_owned_client!(client, session, config)
        client_data = OAuthProtocol.stringify_keys(client)
        raise APIError.new("BAD_REQUEST", message: "public clients cannot rotate secrets") if client_data["public"] || client_data["tokenEndpointAuthMethod"] == "none"

        client_secret = Crypto.random_string(32)
        updated = ctx.context.adapter.update(
          model: "oauthClient",
          where: [{field: "clientId", value: body["client_id"]}],
          update: {clientSecret: OAuthProtocol.store_client_secret_value(ctx, client_secret, config[:store_client_secret]), updatedAt: Time.now}
        )
        response = OAuthProtocol.client_response(updated, include_secret: false)
        ctx.json(response.merge(client_secret: OAuthProtocol.apply_prefix(client_secret, config[:prefix], :client_secret), client_secret_expires_at: client_data["clientSecretExpiresAt"] || 0))
      end
    end

    def oauth_list_consents_endpoint
      Endpoint.new(path: "/oauth2/get-consents", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        consents = ctx.context.adapter.find_many(model: "oauthConsent", where: [{field: "userId", value: session[:user]["id"]}])
        ctx.json(consents.map { |consent| oauth_consent_response(consent) })
      end
    end

    def oauth_get_consent_endpoint
      Endpoint.new(path: "/oauth2/get-consent", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        query = OAuthProtocol.stringify_keys(ctx.query)
        consent = if query["id"].to_s.empty?
          oauth_find_user_consent(ctx, session, query["client_id"])
        else
          ctx.context.adapter.find_one(model: "oauthConsent", where: [{field: "id", value: query["id"]}])
        end
        raise APIError.new("NOT_FOUND", message: "missing id") unless query["id"] || query["client_id"]
        raise APIError.new("NOT_FOUND", message: "consent not found") unless consent
        raise APIError.new("UNAUTHORIZED") unless OAuthProtocol.stringify_keys(consent)["userId"] == session[:user]["id"]

        ctx.json(oauth_consent_response(consent))
      end
    end

    def oauth_update_consent_endpoint
      Endpoint.new(path: "/oauth2/update-consent", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        id = body["id"]
        consent = if id.to_s.empty?
          oauth_find_user_consent(ctx, session, body["client_id"])
        else
          ctx.context.adapter.find_one(model: "oauthConsent", where: [{field: "id", value: id}])
        end
        raise APIError.new("NOT_FOUND", message: "missing id") if id.to_s.empty? && body["client_id"].to_s.empty?
        raise APIError.new("NOT_FOUND", message: "consent not found") unless consent
        consent_data = OAuthProtocol.stringify_keys(consent)
        raise APIError.new("UNAUTHORIZED") unless consent_data["userId"] == session[:user]["id"]

        client = OAuthProtocol.find_client(ctx, "oauthClient", consent_data["clientId"])
        allowed = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(client || {})["scopes"])
        scopes = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(body["update"] || {})["scopes"] || body["scope"] || body["scopes"])
        unless scopes.all? { |scope| allowed.include?(scope) }
          raise APIError.new("BAD_REQUEST", message: "invalid_scope")
        end

        updated = ctx.context.adapter.update(
          model: "oauthConsent",
          where: [{field: "id", value: consent_data["id"]}],
          update: {scopes: scopes, updatedAt: Time.now}
        )
        ctx.json(oauth_consent_response(updated))
      end
    end

    def oauth_delete_consent_endpoint
      Endpoint.new(path: "/oauth2/delete-consent", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        id = body["id"]
        consent = if id.to_s.empty?
          oauth_find_user_consent(ctx, session, body["client_id"])
        else
          ctx.context.adapter.find_one(model: "oauthConsent", where: [{field: "id", value: id}])
        end
        raise APIError.new("NOT_FOUND", message: "missing id") if id.to_s.empty? && body["client_id"].to_s.empty?
        raise APIError.new("NOT_FOUND", message: "consent not found") unless consent
        raise APIError.new("UNAUTHORIZED") unless OAuthProtocol.stringify_keys(consent)["userId"] == session[:user]["id"]

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
      query = oauth_resolve_request_uri!(ctx, config, query)
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

      if prompts.include?("login") && !continue_post_login
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

      consent_reference_id = oauth_consent_reference(config, session, scopes)
      requires_consent = !client_data["skipConsent"] && (prompts.include?("consent") || !oauth_consent_granted?(ctx, client_data["clientId"], session[:user]["id"], scopes, consent_reference_id))

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
          reference_id: consent_reference_id,
          expires_at: Time.now + 600
        }
        raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(config[:consent_page], consent_code: consent_code, client_id: client_data["clientId"], scope: OAuthProtocol.scope_string(scopes)))
      end

      oauth_redirect_with_code(ctx, config, query, session, client, scopes, reference_id: consent_reference_id)
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
        current_session = Routes.current_session(ctx)
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

        reference_id = oauth_consent_reference(config, current_session, granted_scopes) || consent[:reference_id]
        oauth_store_consent(ctx, consent[:client], consent[:session], granted_scopes, reference_id)
        redirect = oauth_authorization_redirect(ctx, config, query, consent[:session], consent[:client], granted_scopes, reference_id: reference_id)
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

    def oauth_authorization_redirect(ctx, config, query, session, client, scopes, reference_id: nil)
      code = Crypto.random_string(32)
      client_reference_id = OAuthProtocol.stringify_keys(client)["referenceId"]
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
        reference_id: reference_id || client_reference_id
      )
      OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], code: code, state: query["state"], iss: OAuthProvider.validate_issuer_url(OAuthProtocol.issuer(ctx)))
    end

    def oauth_redirect_with_code(ctx, config, query, session, client, scopes, reference_id: nil)
      raise ctx.redirect(oauth_authorization_redirect(ctx, config, query, session, client, scopes, reference_id: reference_id))
    end

    def oauth_consent_granted?(ctx, client_id, user_id, scopes, reference_id = nil)
      where = [
        {field: "clientId", value: client_id},
        {field: "userId", value: user_id}
      ]
      where << {field: "referenceId", value: reference_id} if reference_id
      consent = ctx.context.adapter.find_one(
        model: "oauthConsent",
        where: where
      )
      return false unless consent

      granted = OAuthProtocol.parse_scopes(consent["scopes"])
      scopes.all? { |scope| granted.include?(scope) }
    end

    def oauth_store_consent(ctx, client, session, scopes, reference_id = nil)
      client_id = OAuthProtocol.stringify_keys(client)["clientId"]
      user_id = session[:user]["id"]
      where = [
        {field: "clientId", value: client_id},
        {field: "userId", value: user_id}
      ]
      where << {field: "referenceId", value: reference_id} if reference_id
      existing = ctx.context.adapter.find_one(
        model: "oauthConsent",
        where: where
      )
      data = {clientId: client_id, userId: user_id, scopes: scopes}
      data[:referenceId] = reference_id if reference_id
      if existing
        ctx.context.adapter.update(model: "oauthConsent", where: [{field: "id", value: existing.fetch("id")}], update: data)
      else
        ctx.context.adapter.create(model: "oauthConsent", data: data)
      end
    end

    def oauth_consent_reference(config, session, scopes)
      callback = config.dig(:post_login, :consent_reference_id) || config.dig(:post_login, :consentReferenceId)
      return nil unless callback.respond_to?(:call)

      callback.call({user: session[:user], session: session[:session], scopes: scopes})
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

    def oauth_userinfo_endpoint(config)
      Endpoint.new(path: "/oauth2/userinfo", method: "GET") do |ctx|
        ctx.json(OAuthProtocol.userinfo(config[:store], ctx.headers["authorization"], additional_claim: config[:custom_user_info_claims] || config[:additional_claim], prefix: config[:prefix], jwt_secret: ctx.context.secret))
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

    def oauth_resolve_request_uri!(ctx, config, query)
      query = OAuthProtocol.stringify_keys(query)
      return query if query["request_uri"].to_s.empty?

      resolver = config[:request_uri_resolver]
      unless resolver.respond_to?(:call)
        return oauth_invalid_request_uri!(ctx, query, "request_uri not supported")
      end

      resolved = resolver.call({request_uri: query["request_uri"], client_id: query["client_id"], context: ctx})
      return oauth_invalid_request_uri!(ctx, query, "request_uri is invalid or expired") unless resolved

      OAuthProtocol.stringify_keys(resolved)
    end

    def oauth_invalid_request_uri!(ctx, query, description)
      redirect_uri = query["redirect_uri"]
      raise APIError.new("BAD_REQUEST", message: "invalid_request_uri") if redirect_uri.to_s.empty?

      raise ctx.redirect(oauth_authorize_error_redirect(ctx, query, "invalid_request_uri", description))
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

    def oauth_assert_owned_client!(client, session, config = nil)
      data = OAuthProtocol.stringify_keys(client)
      return if data["userId"] && data["userId"] == session[:user]["id"]

      if data["referenceId"] && config && config[:client_reference].respond_to?(:call)
        reference_id = config[:client_reference].call({user: session[:user], session: session[:session]})
        return if data["referenceId"] == reference_id
      end

      raise APIError.new("NOT_FOUND", message: "client not found")
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

    def oauth_client_reference(config, session)
      return nil unless session && config[:client_reference].respond_to?(:call)

      config[:client_reference].call({user: session[:user], session: session[:session]})
    end

    def oauth_client_update_data(source, admin: false)
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
      update["skipConsent"] = !!(source["skip_consent"] || source["skipConsent"]) if admin && (source.key?("skip_consent") || source.key?("skipConsent"))
      update["clientSecretExpiresAt"] = source["client_secret_expires_at"] if admin && source.key?("client_secret_expires_at")
      update["subjectType"] = source["subject_type"] || source["subjectType"] if admin && (source.key?("subject_type") || source.key?("subjectType"))
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
        scopes: OAuthProtocol.parse_scopes(data["scopes"])
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

    def oauth_token_auth_methods(config)
      methods = ["client_secret_basic", "client_secret_post"]
      methods.unshift("none") if config[:allow_unauthenticated_client_registration]
      methods
    end

    def oauth_id_token_signing_algs(ctx, config)
      return ["HS256"] if config[:disable_jwt_plugin]

      jwt_plugin = ctx.context.options.plugins.find { |plugin| plugin.id == "jwt" }
      alg = config.dig(:jwt, :jwks, :key_pair_config, :alg) ||
        jwt_plugin&.options&.dig(:jwks, :key_pair_config, :alg)
      alg ? [alg] : ["EdDSA"]
    end

    def oauth_prompt_values
      ["login", "consent", "create", "select_account", "none"]
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

    def oauth_legacy_get_client_endpoint(config)
      Endpoint.new(path: "/oauth2/client/:id", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "read")
        client = OAuthProtocol.find_client(ctx, "oauthClient", ctx.params["id"] || ctx.params[:id])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)
        ctx.json(OAuthProtocol.client_response(client, include_secret: false))
      end
    end

    def oauth_legacy_get_client_public_endpoint(_config)
      Endpoint.new(path: "/oauth2/client", method: "GET") do |ctx|
        query = OAuthProtocol.stringify_keys(ctx.query)
        client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        ctx.json(OAuthProtocol.client_response(client, include_secret: false))
      end
    end

    def oauth_legacy_list_clients_endpoint(config)
      Endpoint.new(path: "/oauth2/clients", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "list")
        clients = ctx.context.adapter.find_many(model: "oauthClient", where: [{field: "userId", value: session[:user]["id"]}])
        ctx.json(clients.map { |client| OAuthProtocol.client_response(client, include_secret: false) })
      end
    end

    def oauth_legacy_update_client_endpoint(config)
      Endpoint.new(path: "/oauth2/client", method: "PATCH") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "update")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)
        update = oauth_client_update_data(OAuthProtocol.stringify_keys(body["update"] || body))
        updated = update.empty? ? client : ctx.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}], update: update.merge(updatedAt: Time.now))
        ctx.json(OAuthProtocol.client_response(updated, include_secret: false))
      end
    end

    def oauth_legacy_delete_client_endpoint(config)
      Endpoint.new(path: "/oauth2/client", method: "DELETE") do |ctx|
        session = Routes.current_session(ctx)
        oauth_assert_client_privilege!(ctx, config, session, "delete")
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = OAuthProtocol.find_client(ctx, "oauthClient", body["client_id"])
        raise APIError.new("NOT_FOUND", message: "client not found") unless client
        oauth_assert_owned_client!(client, session, config)
        ctx.context.adapter.delete(model: "oauthClient", where: [{field: "clientId", value: body["client_id"]}])
        ctx.json({deleted: true})
      end
    end

    def oauth_legacy_list_consents_endpoint
      Endpoint.new(path: "/oauth2/consents", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        consents = ctx.context.adapter.find_many(model: "oauthConsent", where: [{field: "userId", value: session[:user]["id"]}])
        ctx.json(consents.map { |consent| oauth_consent_response(consent) })
      end
    end

    def oauth_legacy_get_consent_endpoint
      Endpoint.new(path: "/oauth2/consent", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        query = OAuthProtocol.stringify_keys(ctx.query)
        consent = oauth_find_user_consent(ctx, session, query["client_id"])
        raise APIError.new("NOT_FOUND", message: "consent not found") unless consent
        ctx.json(oauth_consent_response(consent))
      end
    end

    def oauth_legacy_update_consent_endpoint
      Endpoint.new(path: "/oauth2/consent", method: "PATCH") do |ctx|
        session = Routes.current_session(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        consent = oauth_find_user_consent(ctx, session, body["client_id"])
        raise APIError.new("NOT_FOUND", message: "consent not found") unless consent
        scopes = OAuthProtocol.parse_scopes(body["scope"] || body["scopes"])
        existing = OAuthProtocol.parse_scopes(OAuthProtocol.stringify_keys(consent)["scopes"])
        raise APIError.new("BAD_REQUEST", message: "invalid_scope") unless scopes.all? { |scope| existing.include?(scope) }

        updated = ctx.context.adapter.update(
          model: "oauthConsent",
          where: [{field: "id", value: OAuthProtocol.stringify_keys(consent)["id"]}],
          update: {scopes: scopes, updatedAt: Time.now}
        )
        ctx.json(oauth_consent_response(updated))
      end
    end

    def oauth_legacy_delete_consent_endpoint
      Endpoint.new(path: "/oauth2/consent", method: "DELETE") do |ctx|
        session = Routes.current_session(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        consent = oauth_find_user_consent(ctx, session, body["client_id"])
        raise APIError.new("NOT_FOUND", message: "consent not found") unless consent
        ctx.context.adapter.delete(model: "oauthConsent", where: [{field: "id", value: OAuthProtocol.stringify_keys(consent)["id"]}])
        ctx.json({deleted: true})
      end
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
            clientSecretExpiresAt: {type: "number", required: false},
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
            token: {type: "string", unique: true, required: true},
            expiresAt: {type: "date", required: true},
            clientId: {type: "string", required: true},
            userId: {type: "string", required: false},
            sessionId: {type: "string", required: false},
            scopes: {type: "string[]", required: true},
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
            createdAt: {type: "date", required: true, default_value: -> { Time.now }},
            updatedAt: {type: "date", required: true, default_value: -> { Time.now }, on_update: -> { Time.now }}
          }
        }
      }
    end
  end
end
