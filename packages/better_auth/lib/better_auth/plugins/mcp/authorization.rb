# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module_function

      def authorize(ctx, config)
        set_cors_headers(ctx)
        query = OAuthProtocol.stringify_keys(ctx.query)
        session = Routes.current_session(ctx, allow_nil: true)
        unless session
          ctx.set_signed_cookie("oidc_login_prompt", JSON.generate(query), ctx.context.secret, max_age: 600, path: "/", same_site: "lax")
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(config[:login_page], query))
        end

        redirect_with_code(ctx, config, query, session)
      end

      def restore_login_prompt(ctx, config)
        cookie = ctx.get_signed_cookie("oidc_login_prompt", ctx.context.secret)
        return unless cookie

        session = ctx.context.new_session
        return unless session && session[:session] && ctx.response_headers["set-cookie"].to_s.include?(ctx.context.auth_cookies[:session_token].name)

        query = parse_login_prompt(cookie)
        return unless query

        query["prompt"] = prompt_without_login(query["prompt"]) if query.key?("prompt")
        ctx.set_cookie("oidc_login_prompt", "", path: "/", max_age: 0)
        ctx.context.set_current_session(session) if ctx.context.respond_to?(:set_current_session)
        [302, ctx.response_headers.merge("location" => authorization_redirect_uri(ctx, config, query, session)), [""]]
      end

      def redirect_with_code(ctx, config, query, session)
        raise ctx.redirect(authorization_redirect_uri(ctx, config, query, session))
      end

      def authorization_redirect_uri(ctx, config, query, session)
        query = OAuthProtocol.stringify_keys(query)
        prompts = OAuthProtocol.parse_scopes(query["prompt"])
        raise ctx.redirect("#{ctx.context.base_url}/error?error=invalid_client") if query["client_id"].to_s.empty?
        unless query["response_type"]
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(ctx.context.base_url + "/error", error: "invalid_request", error_description: "response_type is required"))
        end

        client = OAuthProtocol.find_client(ctx, "oauthClient", query["client_id"])
        raise ctx.redirect("#{ctx.context.base_url}/error?error=invalid_client") unless client
        OAuthProtocol.validate_redirect_uri!(client, query["redirect_uri"])
        client_data = OAuthProtocol.stringify_keys(client)
        raise ctx.redirect("#{ctx.context.base_url}/error?error=client_disabled") if client_data["disabled"]
        raise ctx.redirect("#{ctx.context.base_url}/error?error=unsupported_response_type") unless query["response_type"] == "code"

        scopes = OAuthProtocol.parse_scopes(query["scope"] || "openid")
        allowed_scopes = OAuthProtocol.parse_scopes(client_data["scopes"])
        allowed_scopes = OAuthProtocol.parse_scopes(config[:scopes]) if allowed_scopes.empty?
        invalid_scopes = scopes.reject { |scope| config[:scopes].include?(scope) && allowed_scopes.include?(scope) }
        unless invalid_scopes.empty?
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "invalid_scope", error_description: "The following scopes are invalid: #{invalid_scopes.join(", ")}", state: query["state"]))
        end

        pkce_error = OAuthProtocol.validate_authorize_pkce(client_data, scopes, query["code_challenge"], query["code_challenge_method"])
        if pkce_error
          description = (pkce_error == "PKCE is required") ? "pkce is required" : pkce_error
          raise ctx.redirect(OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "invalid_request", error_description: description, state: query["state"]))
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
          code_challenge_method: query["code_challenge_method"],
          nonce: query["nonce"],
          reference_id: client_data["referenceId"]
        )
        OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], code: code, state: query["state"], iss: validate_issuer_url(OAuthProtocol.issuer(ctx)))
      end

      def prompt_without_login(value)
        prompts = OAuthProtocol.parse_scopes(value)
        prompts.delete("login")
        OAuthProtocol.scope_string(prompts)
      end

      def parse_login_prompt(value)
        parsed = JSON.parse(value.to_s)
        parsed.is_a?(Hash) ? parsed : nil
      rescue JSON::ParserError
        nil
      end
    end
  end
end
