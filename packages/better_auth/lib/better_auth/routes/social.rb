# frozen_string_literal: true

require "uri"
require "securerandom"

module BetterAuth
  module Routes
    def self.sign_in_social
      Endpoint.new(path: "/sign-in/social", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        provider_id = body["provider"].to_s
        provider = social_provider(ctx.context, provider_id)
        raise APIError.new("NOT_FOUND", message: BASE_ERROR_CODES["PROVIDER_NOT_FOUND"]) unless provider

        id_token = fetch_value(body, "idToken")
        if id_token
          data = social_user_from_id_token!(ctx, provider, id_token)
          session_data = persist_social_user(ctx, provider_id, data[:user], data[:account])
          Cookies.set_session_cookie(ctx, session_data)
          next ctx.json({
            redirect: false,
            token: session_data[:session]["token"],
            url: nil,
            user: Schema.parse_output(ctx.context.options, "user", session_data[:user])
          })
        end

        code_verifier = SecureRandom.hex(16)
        state = Crypto.sign_jwt(
          {
            "callbackURL" => body["callbackURL"] || body["callbackUrl"] || body["callback_url"] || "/",
            "errorCallbackURL" => body["errorCallbackURL"] || body["errorCallbackUrl"] || body["error_callback_url"],
            "newUserCallbackURL" => body["newUserCallbackURL"] || body["newUserCallbackUrl"] || body["new_user_callback_url"],
            "requestSignUp" => body["requestSignUp"] || body["request_sign_up"],
            "codeVerifier" => code_verifier
          },
          ctx.context.secret,
          expires_in: 600
        )
        url = call_provider(provider, :create_authorization_url, {
          state: state,
          codeVerifier: code_verifier,
          code_verifier: code_verifier,
          redirectURI: "#{ctx.context.base_url}/callback/#{provider_id}",
          redirect_uri: "#{ctx.context.base_url}/callback/#{provider_id}",
          scopes: body["scopes"],
          loginHint: body["loginHint"] || body["login_hint"]
        })
        ctx.set_header("location", url.to_s) unless body["disableRedirect"] || body["disable_redirect"]
        ctx.json({url: url.to_s, redirect: !(body["disableRedirect"] || body["disable_redirect"])})
      end
    end

    def self.callback_oauth
      Endpoint.new(
        path: "/callback/:providerId",
        method: ["GET", "POST"],
        metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}
      ) do |ctx|
        source = (ctx.method == "POST") ? ctx.body.merge(ctx.query) : ctx.query
        data = normalize_hash(source)
        provider_id = fetch_value(ctx.params, "providerId").to_s
        provider = social_provider(ctx.context, provider_id)
        state = data["state"].to_s
        state_data = Crypto.verify_jwt(state, ctx.context.secret) || {}
        error_url = state_data["errorCallbackURL"] || "#{ctx.context.base_url}/error"

        raise ctx.redirect(oauth_error_url(error_url, data["error"], data["errorDescription"] || data["error_description"])) if data["error"]
        raise ctx.redirect(oauth_error_url(error_url, "oauth_provider_not_found")) unless provider
        raise ctx.redirect(oauth_error_url(error_url, "state_not_found")) if state.empty?
        raise ctx.redirect(oauth_error_url(error_url, "no_code")) if data["code"].to_s.empty?

        tokens = call_provider(provider, :validate_authorization_code, {
          code: data["code"],
          codeVerifier: state_data["codeVerifier"],
          code_verifier: state_data["codeVerifier"],
          redirectURI: "#{ctx.context.base_url}/callback/#{provider_id}",
          redirect_uri: "#{ctx.context.base_url}/callback/#{provider_id}"
        })
        raise ctx.redirect(oauth_error_url(error_url, "invalid_code")) unless tokens

        user_info = call_provider(provider, :get_user_info, token_hash(tokens))
        user = user_info[:user] || user_info["user"] if user_info
        raise ctx.redirect(oauth_error_url(error_url, "unable_to_get_user_info")) unless user
        raise ctx.redirect(oauth_error_url(error_url, "email_not_found")) if fetch_value(user, "email").to_s.empty?

        session_data = persist_social_user(ctx, provider_id, user, token_hash(tokens).merge("accountId" => fetch_value(user, "id").to_s))
        Cookies.set_session_cookie(ctx, session_data)
        callback_url = state_data["callbackURL"] || "/"
        raise ctx.redirect(callback_url)
      end
    end

    def self.link_social
      Endpoint.new(path: "/link-social", method: "POST") do |ctx|
        session = current_session(ctx)
        body = normalize_hash(ctx.body)
        provider_id = body["provider"].to_s
        provider = social_provider(ctx.context, provider_id)
        raise APIError.new("NOT_FOUND", message: BASE_ERROR_CODES["PROVIDER_NOT_FOUND"]) unless provider

        id_token = fetch_value(body, "idToken")
        if id_token
          data = social_user_from_id_token!(ctx, provider, id_token)
          email = fetch_value(data[:user], "email").to_s.downcase
          unless email == session[:user]["email"].to_s.downcase || ctx.context.options.account.dig(:account_linking, :allow_different_emails)
            raise APIError.new("UNAUTHORIZED", message: "Account not linked - different emails not allowed")
          end

          account_id = fetch_value(data[:user], "id").to_s
          existing = ctx.context.internal_adapter.find_accounts(session[:user]["id"]).find do |account|
            account["providerId"] == provider_id && account["accountId"] == account_id
          end
          unless existing
            ctx.context.internal_adapter.create_account(data[:account].merge("userId" => session[:user]["id"]))
          end
          next ctx.json({url: "", status: true, redirect: false})
        end

        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_TOKEN"])
      end
    end

    def self.social_user_from_id_token!(ctx, provider, id_token)
      token = fetch_value(id_token, "token").to_s
      valid = call_provider(provider, :verify_id_token, token, fetch_value(id_token, "nonce"))
      raise APIError.new("UNAUTHORIZED", message: BASE_ERROR_CODES["INVALID_TOKEN"]) unless valid

      user_info = call_provider(provider, :get_user_info, {
        idToken: token,
        id_token: token,
        accessToken: fetch_value(id_token, "accessToken"),
        access_token: fetch_value(id_token, "accessToken"),
        refreshToken: fetch_value(id_token, "refreshToken"),
        refresh_token: fetch_value(id_token, "refreshToken")
      })
      user = user_info[:user] || user_info["user"] if user_info
      raise APIError.new("UNAUTHORIZED", message: BASE_ERROR_CODES["FAILED_TO_GET_USER_INFO"]) unless user
      raise APIError.new("UNAUTHORIZED", message: BASE_ERROR_CODES["USER_EMAIL_NOT_FOUND"]) if fetch_value(user, "email").to_s.empty?

      {
        user: user,
        account: {
          "providerId" => fetch_value(provider, "id").to_s,
          "accountId" => fetch_value(user, "id").to_s,
          "accessToken" => fetch_value(id_token, "accessToken"),
          "refreshToken" => fetch_value(id_token, "refreshToken"),
          "idToken" => token
        }
      }
    end

    def self.persist_social_user(ctx, provider_id, user_info, account_info)
      email = fetch_value(user_info, "email").to_s.downcase
      account_id = (account_info["accountId"] || account_info[:accountId] || account_info[:account_id] || fetch_value(user_info, "id")).to_s
      existing = ctx.context.internal_adapter.find_oauth_user(email, account_id, provider_id)

      if existing && existing[:linked_account]
        user = existing[:user]
      elsif existing
        user = existing[:user]
        ctx.context.internal_adapter.create_account(account_info.merge("providerId" => provider_id, "accountId" => account_id, "userId" => user["id"]))
      else
        created = ctx.context.internal_adapter.create_oauth_user(
          {
            email: email,
            name: fetch_value(user_info, "name").to_s,
            image: fetch_value(user_info, "image"),
            emailVerified: !!fetch_value(user_info, "emailVerified")
          },
          account_info.merge("providerId" => provider_id, "accountId" => account_id)
        )
        user = created[:user]
      end

      session = ctx.context.internal_adapter.create_session(user["id"], false, session_overrides(ctx), true, ctx)
      {session: session, user: user}
    end

    def self.oauth_error_url(base_url, error, description = nil)
      uri = URI.parse(base_url.to_s)
      query = URI.decode_www_form(uri.query.to_s)
      query << ["error", error.to_s]
      query << ["error_description", description.to_s] if description
      uri.query = URI.encode_www_form(query)
      uri.to_s
    end
  end
end
