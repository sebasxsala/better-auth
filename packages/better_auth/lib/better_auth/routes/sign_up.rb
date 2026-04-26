# frozen_string_literal: true

require "uri"

module BetterAuth
  module Routes
    EMAIL_PATTERN = /\A[^@\s]+@[^@\s]+\.[^@\s]+\z/

    def self.sign_up_email
      Endpoint.new(
        path: "/sign-up/email",
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
        if email_config[:enabled] == false || email_config[:disable_sign_up]
          raise APIError.new("BAD_REQUEST", message: "Email and password sign up is not enabled")
        end

        body = normalize_hash(ctx.body)
        name = body["name"].to_s
        email = body["email"].to_s
        password = body["password"]
        image = body["image"]
        callback_url = body["callbackURL"] || body["callbackUrl"] || body["callback_url"]
        remember_me = body.key?("rememberMe") ? body["rememberMe"] : body["remember_me"]

        validate_sign_up_input!(email, password, email_config)

        ctx.context.adapter.transaction do
          existing = ctx.context.internal_adapter.find_user_by_email(email)
          if existing
            raise APIError.new(
              "UNPROCESSABLE_ENTITY",
              message: BASE_ERROR_CODES["USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"]
            )
          end

          hashed_password = Password.hash(password, hasher: email_config.dig(:password, :hash))
          created_user = create_sign_up_user(ctx, body, email, name, image)
          raise APIError.new("UNPROCESSABLE_ENTITY", message: BASE_ERROR_CODES["FAILED_TO_CREATE_USER"]) unless created_user

          ctx.context.internal_adapter.link_account(
            userId: created_user["id"],
            providerId: "credential",
            accountId: created_user["id"],
            password: hashed_password
          )

          send_sign_up_verification_email(ctx, created_user, callback_url)

          if email_config[:auto_sign_in] == false || email_config[:require_email_verification]
            next ctx.json({token: nil, user: Schema.parse_output(options, "user", created_user)})
          end

          dont_remember_me = remember_me == false || remember_me.to_s == "false"
          session = ctx.context.internal_adapter.create_session(
            created_user["id"],
            dont_remember_me,
            session_overrides(ctx),
            true,
            ctx
          )
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["FAILED_TO_CREATE_SESSION"]) unless session

          Cookies.set_session_cookie(ctx, {session: session, user: created_user}, dont_remember_me)
          ctx.json({token: session["token"], user: Schema.parse_output(options, "user", created_user)})
        end
      end
    end

    def self.validate_sign_up_input!(email, password, email_config)
      unless EMAIL_PATTERN.match?(email)
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_EMAIL"])
      end

      unless password.is_a?(String) && !password.empty?
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_PASSWORD"])
      end

      if password.length < email_config[:min_password_length].to_i
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["PASSWORD_TOO_SHORT"])
      end

      if password.length > email_config[:max_password_length].to_i
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["PASSWORD_TOO_LONG"])
      end
    end

    def self.create_sign_up_user(ctx, body, email, name, image)
      reserved = %w[email password name image callbackURL callbackUrl callback_url rememberMe remember_me]
      additional = body.except(*reserved)
      ctx.context.internal_adapter.create_user(
        additional.merge(
          "email" => email.downcase,
          "name" => name,
          "image" => image,
          "emailVerified" => false
        )
      )
    rescue APIError
      raise
    rescue
      raise APIError.new("UNPROCESSABLE_ENTITY", message: BASE_ERROR_CODES["FAILED_TO_CREATE_USER"])
    end

    def self.send_sign_up_verification_email(ctx, user, callback_url)
      verification = ctx.context.options.email_verification
      password_config = ctx.context.options.email_and_password
      send_on_sign_up = verification.key?(:send_on_sign_up) ? verification[:send_on_sign_up] : password_config[:require_email_verification]
      return unless send_on_sign_up

      sender = verification[:send_verification_email]
      return unless sender.respond_to?(:call)

      token = Crypto.sign_jwt(
        {"email" => user["email"].to_s.downcase},
        ctx.context.secret,
        expires_in: verification[:expires_in] || 3600
      )
      callback = URI.encode_www_form_component(callback_url || "/")
      url = "#{ctx.context.base_url}/verify-email?token=#{URI.encode_www_form_component(token)}&callbackURL=#{callback}"
      sender.call({user: user, url: url, token: token}, ctx.request)
    end

    def self.session_overrides(ctx)
      {
        ipAddress: ctx.headers["x-forwarded-for"].to_s.split(",").first.to_s.strip,
        userAgent: ctx.headers["user-agent"].to_s
      }
    end

    def self.normalize_hash(value)
      value.each_with_object({}) do |(key, object_value), result|
        result[Schema.storage_key(key)] = object_value
      end
    end
  end
end
