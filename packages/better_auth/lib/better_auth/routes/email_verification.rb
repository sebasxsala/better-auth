# frozen_string_literal: true

require "uri"

module BetterAuth
  module Routes
    def self.send_verification_email
      Endpoint.new(path: "/send-verification-email", method: "POST") do |ctx|
        sender = ctx.context.options.email_verification[:send_verification_email]
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VERIFICATION_EMAIL_NOT_ENABLED"]) unless sender.respond_to?(:call)

        body = normalize_hash(ctx.body)
        email = body["email"].to_s.downcase
        session = current_session(ctx, allow_nil: true)

        if session
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["EMAIL_MISMATCH"]) if session[:user]["email"] != email
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["EMAIL_ALREADY_VERIFIED"]) if session[:user]["emailVerified"]

          send_verification_email_payload(ctx, session[:user], body["callbackURL"] || body["callbackUrl"] || body["callback_url"])
          next ctx.json({status: true})
        end

        found = ctx.context.internal_adapter.find_user_by_email(email)
        if found && !found[:user]["emailVerified"]
          send_verification_email_payload(ctx, found[:user], body["callbackURL"] || body["callbackUrl"] || body["callback_url"])
        else
          create_email_verification_token(ctx, email)
        end
        ctx.json({status: true})
      end
    end

    def self.verify_email
      Endpoint.new(path: "/verify-email", method: "GET") do |ctx|
        token = fetch_value(ctx.query, "token").to_s
        callback_url = fetch_value(ctx.query, "callbackURL")
        payload = verify_email_token(ctx, token, callback_url)
        email = payload["email"].to_s.downcase
        update_to = payload["updateTo"] || payload["update_to"]
        user_data = ctx.context.internal_adapter.find_user_by_email(email)
        return redirect_or_error(ctx, callback_url, "user_not_found") unless user_data

        user = user_data[:user]
        if update_to
          updated = ctx.context.internal_adapter.update_user_by_email(email, email: update_to, emailVerified: true)
          set_verified_session_cookie(ctx, updated || user.merge("email" => update_to, "emailVerified" => true))
          next redirect_or_json(ctx, callback_url, {status: true, user: Schema.parse_output(ctx.context.options, "user", updated)})
        end

        if user["emailVerified"]
          next redirect_or_json(ctx, callback_url, {status: true, user: nil})
        end

        call_option(ctx.context.options.email_verification[:before_email_verification], user, ctx.request)
        call_option(ctx.context.options.email_verification[:on_email_verification], user, ctx.request)
        updated = ctx.context.internal_adapter.update_user_by_email(email, emailVerified: true)
        call_option(ctx.context.options.email_verification[:after_email_verification], updated, ctx.request)
        set_verified_session_cookie(ctx, updated) if ctx.context.options.email_verification[:auto_sign_in_after_verification]
        redirect_or_json(ctx, callback_url, {status: true, user: nil})
      end
    end

    def self.send_verification_email_payload(ctx, user, callback_url)
      token = create_email_verification_token(ctx, user["email"])
      callback = URI.encode_www_form_component(callback_url || "/")
      url = "#{ctx.context.base_url}/verify-email?token=#{URI.encode_www_form_component(token)}&callbackURL=#{callback}"
      ctx.context.options.email_verification[:send_verification_email].call({user: user, url: url, token: token}, ctx.request)
    end

    def self.create_email_verification_token(ctx, email, update_to: nil, extra: {})
      payload = {"email" => email.to_s.downcase}.merge(extra)
      payload["updateTo"] = update_to if update_to
      Crypto.sign_jwt(payload, ctx.context.secret, expires_in: ctx.context.options.email_verification[:expires_in] || 3600)
    end

    def self.verify_email_token(ctx, token, callback_url)
      payload = Crypto.verify_jwt(token, ctx.context.secret)
      return payload if payload

      redirect_or_error(ctx, callback_url, "invalid_token")
    end

    def self.redirect_or_error(ctx, callback_url, error)
      if callback_url
        separator = callback_url.include?("?") ? "&" : "?"
        raise ctx.redirect("#{callback_url}#{separator}error=#{error}")
      end
      raise APIError.new("UNAUTHORIZED", message: error)
    end

    def self.redirect_or_json(ctx, callback_url, data)
      raise ctx.redirect(callback_url) if callback_url

      ctx.json(data)
    end

    def self.set_verified_session_cookie(ctx, user)
      session = current_session(ctx, allow_nil: true)
      session_data = session ? session[:session] : ctx.context.internal_adapter.create_session(user["id"])
      Cookies.set_session_cookie(ctx, {session: session_data, user: user})
    end

    def self.call_option(callback, user, request)
      callback.call(user, request) if callback.respond_to?(:call)
    end
  end
end
