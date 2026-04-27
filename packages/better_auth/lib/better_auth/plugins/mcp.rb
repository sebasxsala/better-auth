# frozen_string_literal: true

require "json"

module BetterAuth
  module Plugins
    module MCP
      module_function

      def with_mcp_auth(app, resource_metadata_url:)
        lambda do |env|
          authorization = env["HTTP_AUTHORIZATION"].to_s
          unless authorization.start_with?("Bearer ")
            return [
              401,
              {
                "www-authenticate" => %(Bearer resource_metadata="#{resource_metadata_url}"),
                "access-control-expose-headers" => "WWW-Authenticate"
              },
              ["unauthorized"]
            ]
          end

          app.call(env)
        end
      end
    end

    module_function

    def mcp(options = {})
      config = {
        login_page: "/login",
        resource: nil,
        oidc_config: {},
        scopes: %w[openid profile email offline_access],
        store: OAuthProtocol.stores
      }.merge(normalize_hash(options))

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

    def mcp_register_endpoint(_config)
      Endpoint.new(path: "/mcp/register", method: "POST") do |ctx|
        ctx.json(OAuthProtocol.create_client(ctx, model: "oauthApplication", body: ctx.body, default_auth_method: "none"))
      end
    end

    def mcp_authorize_endpoint(config)
      Endpoint.new(path: "/mcp/authorize", method: "GET") do |ctx|
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
      client = OAuthProtocol.find_client(ctx, "oauthApplication", query["client_id"])
      raise APIError.new("BAD_REQUEST", message: "invalid_client") unless client
      OAuthProtocol.validate_redirect_uri!(client, query["redirect_uri"])

      code = Crypto.random_string(32)
      OAuthProtocol.store_code(
        config[:store],
        code: code,
        client_id: query["client_id"],
        redirect_uri: query["redirect_uri"],
        session: session,
        scopes: query["scope"] || "openid",
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
      Endpoint.new(path: "/mcp/token", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        ctx.set_header("Access-Control-Allow-Origin", "*")
        ctx.set_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        ctx.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
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

    def mcp_userinfo_endpoint(config)
      Endpoint.new(path: "/mcp/userinfo", method: "GET") do |ctx|
        ctx.json(OAuthProtocol.userinfo(config[:store], ctx.headers["authorization"]))
      end
    end

    def mcp_jwks_endpoint(config)
      Endpoint.new(path: "/mcp/jwks", method: "GET") do |ctx|
        jwt_config = config[:jwt] || {}
        create_jwk(ctx, jwt_config) if all_jwks(ctx, jwt_config).empty?
        ctx.json({keys: public_jwks(ctx, jwt_config).map { |key| public_jwk(key, jwt_config) }})
      end
    end
  end
end
