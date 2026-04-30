# frozen_string_literal: true

require "json"

module BetterAuth
  module Plugins
    module MCP
      module_function

      def with_mcp_auth(app, resource_metadata_url:, auth: nil)
        lambda do |env|
          authorization = env["HTTP_AUTHORIZATION"].to_s
          unless authorization.start_with?("Bearer ")
            return unauthorized(resource_metadata_url)
          end

          session = auth&.api&.get_mcp_session(headers: {"authorization" => authorization})
          return unauthorized(resource_metadata_url) unless session

          env["better_auth.mcp_session"] = session

          app.call(env)
        rescue APIError
          unauthorized(resource_metadata_url)
        end
      end

      def unauthorized(resource_metadata_url)
        [
          401,
          {
            "www-authenticate" => %(Bearer resource_metadata="#{resource_metadata_url}"),
            "access-control-expose-headers" => "WWW-Authenticate"
          },
          ["unauthorized"]
        ]
      end
    end

    module_function

    def mcp(options = {})
      config = {
        login_page: "/login",
        consent_page: "/oauth/consent",
        resource: nil,
        oidc_config: {},
        code_expires_in: 600,
        default_scope: "openid",
        access_token_expires_in: 3600,
        refresh_token_expires_in: 604_800,
        allow_plain_code_challenge_method: true,
        scopes: %w[openid profile email offline_access],
        store: OAuthProtocol.stores
      }.merge(normalize_hash(options))
      config = mcp_normalize_config(config)

      Plugin.new(
        id: "mcp",
        endpoints: mcp_endpoints(config),
        hooks: {
          after: [
            {
              matcher: ->(_ctx) { true },
              handler: ->(ctx) { mcp_restore_login_prompt(ctx, config) }
            }
          ]
        },
        schema: oidc_provider_schema,
        options: config
      )
    end

    def mcp_endpoints(config)
      {
        get_mcp_o_auth_config: mcp_oauth_config_endpoint(config),
        get_mcp_protected_resource: mcp_protected_resource_endpoint(config),
        mcp_o_auth_authorize: mcp_authorize_endpoint(config),
        mcp_o_auth_token: mcp_token_endpoint(config),
        mcp_o_auth_user_info: mcp_userinfo_endpoint(config),
        mcp_register: mcp_register_endpoint(config),
        get_mcp_session: mcp_get_session_endpoint(config),
        o_auth_consent: oidc_consent_endpoint(config),
        mcp_jwks: mcp_jwks_endpoint(config)
      }
    end

    def mcp_oauth_config_endpoint(config)
      Endpoint.new(path: "/.well-known/oauth-authorization-server", method: "GET", metadata: {hide: true}) do |ctx|
        base = OAuthProtocol.endpoint_base(ctx)
        ctx.json({
          issuer: OAuthProtocol.issuer(ctx),
          authorization_endpoint: "#{base}/mcp/authorize",
          token_endpoint: "#{base}/mcp/token",
          userinfo_endpoint: "#{base}/mcp/userinfo",
          jwks_uri: "#{base}/mcp/jwks",
          registration_endpoint: "#{base}/mcp/register",
          scopes_supported: config[:scopes],
          response_types_supported: ["code"],
          response_modes_supported: ["query"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          acr_values_supported: ["urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256", "none"],
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
          code_challenge_methods_supported: ["S256"],
          claims_supported: %w[sub iss aud exp nbf iat jti email email_verified name]
        }.merge(config[:oidc_config][:metadata] || {}))
      end
    end

    def mcp_protected_resource_endpoint(config)
      Endpoint.new(path: "/.well-known/oauth-protected-resource", method: "GET", metadata: {hide: true}) do |ctx|
        origin = OAuthProtocol.origin_for(OAuthProtocol.endpoint_base(ctx))
        ctx.json({
          resource: config[:resource] || origin,
          authorization_servers: [origin],
          jwks_uri: config.dig(:oidc_config, :metadata, :jwks_uri) || "#{OAuthProtocol.endpoint_base(ctx)}/mcp/jwks",
          scopes_supported: config.dig(:oidc_config, :metadata, :scopes_supported) || config[:scopes],
          bearer_methods_supported: ["header"],
          resource_signing_alg_values_supported: ["RS256", "none"]
        })
      end
    end

    def mcp_register_endpoint(config)
      Endpoint.new(path: "/mcp/register", method: "POST", metadata: mcp_openapi("registerMcpClient", "Register an OAuth2 application", "OAuth2 application registered successfully", mcp_client_schema)) do |ctx|
        mcp_set_cors_headers(ctx)
        ctx.json(
          OAuthProtocol.create_client(
            ctx,
            model: "oauthApplication",
            body: ctx.body,
            default_auth_method: "none",
            store_client_secret: config[:store_client_secret] || "plain"
          ),
          status: 201,
          headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"}
        )
      end
    end

    def mcp_authorize_endpoint(config)
      Endpoint.new(path: "/mcp/authorize", method: "GET", metadata: mcp_openapi("mcpOAuthAuthorize", "Authorize an OAuth2 request using MCP", "Authorization response generated successfully", {type: "object", additionalProperties: true})) do |ctx|
        query = OAuthProtocol.stringify_keys(ctx.query)
        session = Routes.current_session(ctx, allow_nil: true)
        unless session
          ctx.set_signed_cookie("oidc_login_prompt", JSON.generate(query), ctx.context.secret, max_age: 600, path: "/", same_site: "lax")
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(config[:login_page], query))
        end

        raise ctx.redirect(mcp_authorization_redirect(ctx, config, query, session))
      end
    end

    def mcp_restore_login_prompt(ctx, config)
      cookie = ctx.get_signed_cookie("oidc_login_prompt", ctx.context.secret)
      return unless cookie

      session = ctx.context.new_session
      return unless session && session[:session] && ctx.response_headers["set-cookie"].to_s.include?(ctx.context.auth_cookies[:session_token].name)

      query = mcp_parse_login_prompt(cookie)
      return unless query

      ctx.set_cookie("oidc_login_prompt", "", path: "/", max_age: 0)
      ctx.context.set_current_session(session) if ctx.context.respond_to?(:set_current_session)
      [302, ctx.response_headers.merge("location" => mcp_authorization_redirect(ctx, config, query, session)), [""]]
    end

    def mcp_authorization_redirect(ctx, config, query, session)
      query = OAuthProtocol.stringify_keys(query)
      query["prompt"] = mcp_prompt_without_login(query["prompt"]) if query.key?("prompt")
      prompts = OIDCProvider.parse_prompt(query["prompt"])
      unless query["client_id"]
        raise ctx.redirect("#{ctx.context.base_url}/error?error=invalid_client")
      end
      unless query["response_type"]
        raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(ctx.context.base_url + "/error", error: "invalid_request", error_description: "response_type is required"))
      end
      client = OAuthProtocol.find_client(ctx, "oauthApplication", query["client_id"])
      raise ctx.redirect("#{ctx.context.base_url}/error?error=invalid_client") unless client
      OAuthProtocol.validate_redirect_uri!(client, query["redirect_uri"])
      client_data = OAuthProtocol.stringify_keys(client)
      raise ctx.redirect("#{ctx.context.base_url}/error?error=client_disabled") if client_data["disabled"]
      unless query["response_type"] == "code"
        raise ctx.redirect("#{ctx.context.base_url}/error?error=unsupported_response_type")
      end

      scopes = OAuthProtocol.parse_scopes(query["scope"] || config[:default_scope])
      invalid_scopes = scopes.reject { |scope| config[:scopes].include?(scope) }
      unless invalid_scopes.empty?
        redirect = OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "invalid_scope", error_description: "The following scopes are invalid: #{invalid_scopes.join(", ")}", state: query["state"])
        raise ctx.redirect(redirect)
      end
      if config[:require_pkce] && (query["code_challenge"].to_s.empty? || query["code_challenge_method"].to_s.empty?)
        redirect = OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "invalid_request", error_description: "pkce is required", state: query["state"])
        raise ctx.redirect(redirect)
      end
      challenge_method = query["code_challenge_method"].to_s
      if challenge_method.empty?
        query["code_challenge_method"] = "plain" if query["code_challenge"]
      elsif !valid_code_challenge_method?(challenge_method, config)
        redirect = OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "invalid_request", error_description: "invalid code_challenge method", state: query["state"])
        raise ctx.redirect(redirect)
      end

      if prompts.include?("consent")
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
      OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], code: code, state: query["state"])
    end

    def mcp_prompt_without_login(value)
      prompts = value.to_s.split(/\s+/).reject(&:empty?)
      prompts.delete("login")
      prompts.join(" ")
    end

    def mcp_parse_login_prompt(value)
      parsed = JSON.parse(value.to_s)
      parsed.is_a?(Hash) ? parsed : nil
    rescue JSON::ParserError
      nil
    end

    def mcp_token_endpoint(config)
      Endpoint.new(
        path: "/mcp/token",
        method: "POST",
        metadata: mcp_openapi("mcpOAuthToken", "Exchange OAuth2 code for MCP tokens", "OAuth2 tokens issued successfully", mcp_token_response_schema).merge(allowed_media_types: ["application/x-www-form-urlencoded", "application/json"])
      ) do |ctx|
        mcp_set_cors_headers(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        client = mcp_authenticate_token_client!(ctx, body, config)
        raise APIError.new("UNAUTHORIZED", message: "invalid_client") unless client

        response = case body["grant_type"]
        when OAuthProtocol::AUTH_CODE_GRANT
          client_data = OAuthProtocol.stringify_keys(client)
          if client_data["type"] == "public" && body["code_verifier"].to_s.empty?
            raise APIError.new("BAD_REQUEST", message: "invalid_request")
          end
          code = OAuthProtocol.consume_code!(
            config[:store],
            body["code"],
            client_id: client_data["clientId"],
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
            issuer: OAuthProtocol.issuer(ctx),
            access_token_expires_in: config[:access_token_expires_in]
          )
        when OAuthProtocol::REFRESH_GRANT
          OAuthProtocol.refresh_tokens(ctx, config[:store], model: "oauthAccessToken", client: client, refresh_token: body["refresh_token"], scopes: body["scope"], issuer: OAuthProtocol.issuer(ctx), access_token_expires_in: config[:access_token_expires_in])
        else
          raise APIError.new("BAD_REQUEST", message: "unsupported_grant_type")
        end
        ctx.json(response, headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"})
      end
    end

    def mcp_userinfo_endpoint(config)
      Endpoint.new(path: "/mcp/userinfo", method: "GET", metadata: mcp_openapi("mcpOAuthUserinfo", "Get MCP OAuth2 user information", "User information retrieved successfully", mcp_userinfo_schema)) do |ctx|
        ctx.json(OAuthProtocol.userinfo(config[:store], ctx.headers["authorization"]))
      end
    end

    def mcp_get_session_endpoint(config)
      Endpoint.new(path: "/mcp/get-session", method: "GET", metadata: mcp_openapi("getMcpSession", "Get the MCP session", "MCP session retrieved successfully", {type: ["object", "null"]})) do |ctx|
        authorization = ctx.headers["authorization"].to_s
        token = authorization.start_with?("Bearer ") ? authorization.delete_prefix("Bearer ").strip : ""
        next ctx.json(nil) if token.empty?

        ctx.json(OAuthProtocol.token_record(config[:store], token))
      end
    end

    def mcp_jwks_endpoint(config)
      Endpoint.new(path: "/mcp/jwks", method: "GET", metadata: mcp_openapi("getMcpJSONWebKeySet", "Get the MCP JSON Web Key Set", "JSON Web Key Set retrieved successfully", mcp_jwks_response_schema)) do |ctx|
        jwt_config = config[:jwt] || {}
        create_jwk(ctx, jwt_config) if all_jwks(ctx, jwt_config).empty?
        ctx.json({keys: public_jwks(ctx, jwt_config).map { |key| public_jwk(key, jwt_config) }})
      end
    end

    def mcp_openapi(operation_id, description, response_description, response_schema)
      {
        openapi: {
          operationId: operation_id,
          description: description,
          responses: {
            "200" => OpenAPI.json_response(response_description, response_schema)
          }
        }
      }
    end

    def mcp_client_schema
      OpenAPI.object_schema(
        {
          clientId: {type: "string"},
          clientSecret: {type: ["string", "null"]},
          name: {type: ["string", "null"]},
          redirectUris: {type: "array", items: {type: "string"}}
        },
        required: ["clientId"]
      )
    end

    def mcp_token_response_schema
      OpenAPI.object_schema(
        {
          access_token: {type: "string"},
          token_type: {type: "string"},
          expires_in: {type: "number"},
          refresh_token: {type: ["string", "null"]},
          scope: {type: ["string", "null"]}
        },
        required: ["access_token", "token_type", "expires_in"]
      )
    end

    def mcp_userinfo_schema
      OpenAPI.object_schema(
        {
          sub: {type: "string"},
          email: {type: ["string", "null"]},
          email_verified: {type: ["boolean", "null"]},
          name: {type: ["string", "null"]}
        },
        required: ["sub"]
      )
    end

    def mcp_jwks_response_schema
      OpenAPI.object_schema(
        {keys: {type: "array", items: {type: "object"}}},
        required: ["keys"]
      )
    end

    def mcp_normalize_config(config)
      oidc = normalize_hash(config[:oidc_config] || {})
      merged = config.merge(oidc.except(:metadata))
      merged[:scopes] = (Array(config[:scopes]) + Array(oidc[:scopes])).compact.map(&:to_s).uniq
      merged
    end

    def mcp_set_cors_headers(ctx)
      ctx.set_header("Access-Control-Allow-Origin", "*")
      ctx.set_header("Access-Control-Allow-Methods", "POST, OPTIONS")
      ctx.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
      ctx.set_header("Access-Control-Max-Age", "86400")
    end

    def mcp_authenticate_token_client!(ctx, body, config)
      authorization = ctx.headers["authorization"].to_s
      if authorization.start_with?("Basic ") && body["client_id"].to_s.empty?
        return OAuthProtocol.authenticate_client!(ctx, "oauthApplication", store_client_secret: config[:store_client_secret] || "plain")
      end

      client = OAuthProtocol.find_client(ctx, "oauthApplication", body["client_id"])
      raise APIError.new("UNAUTHORIZED", message: "invalid_client") unless client

      data = OAuthProtocol.stringify_keys(client)
      method = data["tokenEndpointAuthMethod"] || "client_secret_basic"
      if method != "none" && !OAuthProtocol.verify_client_secret(ctx, data["clientSecret"], body["client_secret"], config[:store_client_secret] || "plain")
        raise APIError.new("UNAUTHORIZED", message: "invalid_client")
      end
      client
    end
  end
end
