# frozen_string_literal: true

require "uri"

module BetterAuth
  module Routes
    def self.sign_in_email
      Endpoint.new(
        path: "/sign-in/email",
        method: "POST",
        metadata: {
          allowed_media_types: [
            "application/x-www-form-urlencoded",
            "application/json"
          ]
        }
      ) do |ctx|
        options = ctx.context.options
        email_config = options.email_and_password
        if email_config[:enabled] == false
          raise APIError.new("BAD_REQUEST", message: "Email and password is not enabled")
        end

        body = normalize_hash(ctx.body)
        email = body["email"].to_s
        password = body["password"].to_s
        callback_url = body["callbackURL"] || body["callbackUrl"] || body["callback_url"]
        remember_me = body.key?("rememberMe") ? body["rememberMe"] : body["remember_me"]

        unless EMAIL_PATTERN.match?(email)
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_EMAIL"])
        end

        found = ctx.context.internal_adapter.find_user_by_email(email, include_accounts: true)
        unless found
          Password.hash(password)
          raise APIError.new("UNAUTHORIZED", message: BASE_ERROR_CODES["INVALID_EMAIL_OR_PASSWORD"])
        end

        user = found[:user] || found["user"]
        accounts = found[:accounts] || found["accounts"] || []
        credential_account = accounts.find { |account| account["providerId"] == "credential" || account[:providerId] == "credential" }
        current_password = credential_account && (credential_account["password"] || credential_account[:password])
        unless current_password && Password.verify(password: password, hash: current_password, verifier: email_config.dig(:password, :verify))
          Password.hash(password) unless current_password
          raise APIError.new("UNAUTHORIZED", message: BASE_ERROR_CODES["INVALID_EMAIL_OR_PASSWORD"])
        end

        if email_config[:require_email_verification] && !user["emailVerified"]
          send_sign_in_verification_email(ctx, user, callback_url)
          raise APIError.new("FORBIDDEN", message: BASE_ERROR_CODES["EMAIL_NOT_VERIFIED"])
        end

        dont_remember_me = remember_me == false || remember_me.to_s == "false"
        session = ctx.context.internal_adapter.create_session(
          user["id"],
          dont_remember_me,
          session_overrides(ctx),
          true
        )
        raise APIError.new("UNAUTHORIZED", message: BASE_ERROR_CODES["FAILED_TO_CREATE_SESSION"]) unless session

        Cookies.set_session_cookie(ctx, {session: session, user: user}, dont_remember_me)
        ctx.set_header("location", callback_url) if callback_url
        ctx.json({
          redirect: !!callback_url,
          token: session["token"],
          url: callback_url,
          user: Schema.parse_output(options, "user", user)
        })
      end
    end

    def self.send_sign_in_verification_email(ctx, user, callback_url)
      verification = ctx.context.options.email_verification
      sender = verification[:send_verification_email]
      return unless verification[:send_on_sign_in] && sender.respond_to?(:call)

      token = Crypto.sign_jwt(
        {"email" => user["email"].to_s.downcase},
        ctx.context.secret,
        expires_in: verification[:expires_in] || 3600
      )
      callback = URI.encode_www_form_component(callback_url || "/")
      url = "#{ctx.context.base_url}/verify-email?token=#{URI.encode_www_form_component(token)}&callbackURL=#{callback}"
      sender.call({user: user, url: url, token: token}, ctx.request)
    end
  end
end
