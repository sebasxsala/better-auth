# frozen_string_literal: true

require "net/http"
require "uri"

module BetterAuth
  module Plugins
    module_function

    GENERIC_OAUTH_ERROR_CODES = {
      "INVALID_OAUTH_CONFIGURATION" => "Invalid OAuth configuration",
      "TOKEN_URL_NOT_FOUND" => "Invalid OAuth configuration. Token URL not found.",
      "PROVIDER_CONFIG_NOT_FOUND" => "No config found for provider",
      "PROVIDER_ID_REQUIRED" => "Provider ID is required",
      "INVALID_OAUTH_CONFIG" => "Invalid OAuth configuration.",
      "SESSION_REQUIRED" => "Session is required",
      "ISSUER_MISMATCH" => "OAuth issuer mismatch. The authorization server issuer does not match the expected value (RFC 9207).",
      "ISSUER_MISSING" => "OAuth issuer parameter missing. The authorization server did not include the required iss parameter (RFC 9207)."
    }.freeze

    def generic_oauth(options = {})
      config = normalize_hash(options)
      providers = Array(config[:config]).map { |provider| normalize_hash(provider) }
      generic_oauth_warn_duplicate_providers(providers)
      config[:config] = providers

      Plugin.new(
        id: "generic-oauth",
        endpoints: {
          sign_in_with_oauth2: sign_in_with_oauth2_endpoint(config),
          o_auth2_callback: o_auth2_callback_endpoint(config),
          o_auth2_link_account: o_auth2_link_account_endpoint(config)
        },
        error_codes: GENERIC_OAUTH_ERROR_CODES,
        options: config
      )
    end

    def sign_in_with_oauth2_endpoint(config)
      Endpoint.new(path: "/sign-in/oauth2", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        provider_id = body[:provider_id].to_s
        provider = generic_oauth_provider!(config, provider_id)
        auth_url = generic_oauth_authorization_url(ctx, provider, body, link: nil)
        ctx.json({url: auth_url, redirect: !body[:disable_redirect]})
      end
    end

    def o_auth2_link_account_endpoint(config)
      Endpoint.new(path: "/oauth2/link", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        provider_id = body[:provider_id].to_s
        provider = generic_oauth_provider(config, provider_id)
        raise APIError.new("NOT_FOUND", message: BASE_ERROR_CODES["PROVIDER_NOT_FOUND"]) unless provider

        auth_url = generic_oauth_authorization_url(
          ctx,
          provider,
          body,
          link: {user_id: session[:user]["id"], email: session[:user]["email"]}
        )
        ctx.json({url: auth_url, redirect: true})
      end
    end

    def o_auth2_callback_endpoint(config)
      Endpoint.new(
        path: "/oauth2/callback/:providerId",
        method: ["GET", "POST"],
        metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}
      ) do |ctx|
        query = normalize_hash(ctx.query)
        provider_id = (fetch_value(ctx.params, "providerId") || query[:provider_id]).to_s
        raise APIError.new("BAD_REQUEST", message: GENERIC_OAUTH_ERROR_CODES["PROVIDER_ID_REQUIRED"]) if provider_id.empty?

        provider = generic_oauth_provider!(config, provider_id)
        state_data = Crypto.verify_jwt(query[:state].to_s, ctx.context.secret) || {}
        error_url = state_data["errorURL"] || state_data["errorCallbackURL"] || "#{ctx.context.base_url}/error"
        redirect_error = ->(error) { raise ctx.redirect(generic_oauth_error_url(error_url, error)) }

        redirect_error.call(query[:error] || "oAuth_code_missing") if query[:error] || query[:code].to_s.empty?
        generic_oauth_validate_issuer!(ctx, provider, query, redirect_error)

        tokens = generic_oauth_exchange_token(ctx, provider, query[:code].to_s, state_data)
        redirect_error.call("oauth_code_verification_failed") unless tokens
        user_info = generic_oauth_user_info(provider, tokens)
        redirect_error.call("user_info_is_missing") unless user_info

        mapped_user = generic_oauth_map_user(provider, user_info)
        email = fetch_value(mapped_user, "email").to_s.downcase
        name = fetch_value(mapped_user, "name").to_s
        account_id = fetch_value(mapped_user, "id").to_s
        redirect_error.call("email_is_missing") if email.empty?
        redirect_error.call("name_is_missing") if name.empty?

        link = state_data["link"]
        callback_url = state_data["callbackURL"] || "/"
        if link
          generic_oauth_link_account(ctx, provider, tokens, mapped_user, link, redirect_error)
          raise ctx.redirect(callback_url)
        end

        existing = ctx.context.internal_adapter.find_oauth_user(email, account_id, provider_id)
        if !existing && (provider[:disable_sign_up] || (provider[:disable_implicit_sign_up] && !state_data["requestSignUp"]))
          redirect_error.call("signup_disabled")
        end

        session_data = Routes.persist_social_user(
          ctx,
          provider_id,
          mapped_user.merge("email" => email, "name" => name, "id" => account_id),
          generic_oauth_account_info(provider_id, account_id, tokens)
        )
        Cookies.set_session_cookie(ctx, session_data)
        raise ctx.redirect(existing ? callback_url : (state_data["newUserURL"] || state_data["newUserCallbackURL"] || callback_url))
      end
    end

    def generic_oauth_authorization_url(ctx, provider, body, link:)
      authorization_url = provider[:authorization_url] || generic_oauth_discovery(provider)["authorization_endpoint"]
      token_url = provider[:token_url] || generic_oauth_discovery(provider)["token_endpoint"]
      raise APIError.new("BAD_REQUEST", message: GENERIC_OAUTH_ERROR_CODES["INVALID_OAUTH_CONFIGURATION"]) if authorization_url.to_s.empty? || token_url.to_s.empty?

      code_verifier = Crypto.random_string(43)
      state = Crypto.sign_jwt(
        {
          "callbackURL" => body[:callback_url] || body[:callbackURL] || "/",
          "errorURL" => body[:error_callback_url] || body[:errorCallbackURL],
          "newUserURL" => body[:new_user_callback_url] || body[:newUserCallbackURL],
          "requestSignUp" => body[:request_sign_up] || body[:requestSignUp],
          "codeVerifier" => code_verifier,
          "link" => link
        },
        ctx.context.secret,
        expires_in: 600
      )

      uri = URI.parse(authorization_url.to_s)
      params = URI.decode_www_form(uri.query.to_s)
      params.concat([
        ["client_id", provider[:client_id].to_s],
        ["response_type", provider[:response_type] || "code"],
        ["redirect_uri", generic_oauth_redirect_uri(ctx, provider)],
        ["state", state]
      ])
      scopes = Array(body[:scopes]) + Array(provider[:scopes])
      params << ["scope", scopes.join(" ")] unless scopes.empty?
      params << ["code_challenge", code_verifier] if provider[:pkce]
      params << ["code_challenge_method", "plain"] if provider[:pkce]
      params << ["prompt", provider[:prompt]] if provider[:prompt]
      params << ["access_type", provider[:access_type]] if provider[:access_type]
      normalize_hash(provider[:authorization_url_params] || {}).each { |key, value| params << [key.to_s, value.to_s] }
      uri.query = URI.encode_www_form(params)
      uri.to_s
    end

    def generic_oauth_exchange_token(ctx, provider, code, state_data)
      token_callback = provider[:get_token]
      if token_callback.respond_to?(:call)
        return normalize_hash(token_callback.call(
          code: code,
          redirectURI: generic_oauth_redirect_uri(ctx, provider),
          redirect_uri: generic_oauth_redirect_uri(ctx, provider),
          codeVerifier: state_data["codeVerifier"],
          code_verifier: state_data["codeVerifier"]
        ))
      end

      token_url = provider[:token_url] || generic_oauth_discovery(provider)["token_endpoint"]
      raise APIError.new("BAD_REQUEST", message: GENERIC_OAUTH_ERROR_CODES["TOKEN_URL_NOT_FOUND"]) if token_url.to_s.empty?

      generic_oauth_post_token(token_url, provider, code, state_data["codeVerifier"], generic_oauth_redirect_uri(ctx, provider))
    end

    def generic_oauth_user_info(provider, tokens)
      callback = provider[:get_user_info]
      return normalize_hash(callback.call(tokens)) if callback.respond_to?(:call)

      id_token = tokens[:id_token] || tokens[:idToken]
      return generic_oauth_user_from_id_token(id_token) if id_token

      user_info_url = provider[:user_info_url] || generic_oauth_discovery(provider)["userinfo_endpoint"]
      return nil if user_info_url.to_s.empty?

      uri = URI(user_info_url)
      request = Net::HTTP::Get.new(uri)
      request["authorization"] = "Bearer #{tokens[:access_token] || tokens[:accessToken]}"
      response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |http| http.request(request) }
      return nil unless response.is_a?(Net::HTTPSuccess)

      normalize_hash(JSON.parse(response.body))
    rescue
      nil
    end

    def generic_oauth_map_user(provider, user_info)
      mapper = provider[:map_profile_to_user]
      mapped = mapper.respond_to?(:call) ? mapper.call(user_info) : user_info
      normalize_hash(user_info).merge(normalize_hash(mapped || {}))
    end

    def generic_oauth_link_account(ctx, provider, tokens, user_info, link, redirect_error)
      if !ctx.context.options.account.dig(:account_linking, :allow_different_emails) &&
          link["email"].to_s.downcase != fetch_value(user_info, "email").to_s.downcase
        redirect_error.call("email_doesn't_match")
      end

      account_id = fetch_value(user_info, "id").to_s
      existing_account = ctx.context.internal_adapter.find_account_by_provider_id(account_id, provider[:provider_id].to_s)
      account_info = generic_oauth_account_info(provider[:provider_id].to_s, account_id, tokens).merge("userId" => link["user_id"])
      if existing_account
        redirect_error.call("account_already_linked_to_different_user") if existing_account["userId"] != link["user_id"]
        ctx.context.internal_adapter.update_account(existing_account["id"], account_info)
      else
        ctx.context.internal_adapter.create_account(account_info)
      end
    end

    def generic_oauth_account_info(provider_id, account_id, tokens)
      data = normalize_hash(tokens || {})
      {
        "providerId" => provider_id,
        "accountId" => account_id,
        "accessToken" => data[:access_token] || data[:accessToken],
        "refreshToken" => data[:refresh_token] || data[:refreshToken],
        "idToken" => data[:id_token] || data[:idToken],
        "accessTokenExpiresAt" => data[:access_token_expires_at] || data[:accessTokenExpiresAt],
        "refreshTokenExpiresAt" => data[:refresh_token_expires_at] || data[:refreshTokenExpiresAt],
        "scope" => Array(data[:scopes] || data[:scope]).join(",")
      }
    end

    def generic_oauth_provider!(config, provider_id)
      provider = generic_oauth_provider(config, provider_id)
      raise APIError.new("BAD_REQUEST", message: "#{GENERIC_OAUTH_ERROR_CODES["PROVIDER_CONFIG_NOT_FOUND"]} #{provider_id}") unless provider

      provider
    end

    def generic_oauth_provider(config, provider_id)
      Array(config[:config]).find { |provider| provider[:provider_id].to_s == provider_id.to_s }
    end

    def generic_oauth_redirect_uri(ctx, provider)
      provider[:redirect_uri] || provider[:redirectURI] || "#{ctx.context.base_url}/oauth2/callback/#{provider[:provider_id]}"
    end

    def generic_oauth_validate_issuer!(ctx, provider, query, redirect_error)
      expected = provider[:issuer] || generic_oauth_discovery(provider)["issuer"]
      return if expected.to_s.empty?
      return if query[:iss].to_s == expected.to_s
      return redirect_error.call("issuer_missing") if query[:iss].to_s.empty? && provider[:require_issuer_validation]
      return if query[:iss].to_s.empty?

      redirect_error.call("issuer_mismatch")
    end

    def generic_oauth_discovery(provider)
      return {} if provider[:discovery_url].to_s.empty?
      return provider[:_discovery] if provider[:_discovery]

      uri = URI(provider[:discovery_url])
      response = Net::HTTP.get_response(uri)
      provider[:_discovery] = response.is_a?(Net::HTTPSuccess) ? JSON.parse(response.body) : {}
    rescue
      {}
    end

    def generic_oauth_post_token(token_url, provider, code, code_verifier, redirect_uri)
      uri = URI(token_url)
      request = Net::HTTP::Post.new(uri)
      request.set_form_data({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirect_uri,
        client_id: provider[:client_id],
        client_secret: provider[:client_secret],
        code_verifier: code_verifier
      }.compact)
      response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |http| http.request(request) }
      return nil unless response.is_a?(Net::HTTPSuccess)

      normalize_hash(JSON.parse(response.body))
    rescue
      nil
    end

    def generic_oauth_user_from_id_token(id_token)
      payload = JWT.decode(id_token, nil, false).first
      normalize_hash(
        id: payload["sub"],
        email: payload["email"],
        emailVerified: payload["email_verified"],
        name: payload["name"],
        image: payload["picture"]
      )
    rescue
      nil
    end

    def generic_oauth_error_url(base_url, error)
      uri = URI.parse(base_url.to_s)
      query = URI.decode_www_form(uri.query.to_s)
      query << ["error", error.to_s]
      uri.query = URI.encode_www_form(query)
      uri.to_s
    end

    def generic_oauth_warn_duplicate_providers(providers)
      duplicates = providers.group_by { |provider| provider[:provider_id].to_s }.select { |id, entries| !id.empty? && entries.length > 1 }.keys
      warn "Duplicate provider IDs found: #{duplicates.join(", ")}" unless duplicates.empty?
    end
  end
end
