# frozen_string_literal: true

module BetterAuth
  module Plugins
    EMAIL_OTP_ERROR_CODES = {
      "OTP_EXPIRED" => "OTP expired",
      "INVALID_OTP" => "Invalid OTP",
      "TOO_MANY_ATTEMPTS" => "Too many attempts"
    }.freeze

    module_function

    def email_otp(options = {})
      config = {
        expires_in: 5 * 60,
        otp_length: 6,
        store_otp: "plain",
        allowed_attempts: 3
      }.merge(normalize_hash(options))

      Plugin.new(
        id: "email-otp",
        init: email_otp_init(config),
        endpoints: {
          send_verification_otp: send_verification_otp_endpoint(config),
          create_verification_otp: create_verification_otp_endpoint(config),
          get_verification_otp: get_verification_otp_endpoint(config),
          check_verification_otp: check_verification_otp_endpoint(config),
          verify_email_otp: verify_email_otp_endpoint(config),
          sign_in_email_otp: sign_in_email_otp_endpoint(config),
          request_password_reset_email_otp: request_password_reset_email_otp_endpoint(config),
          forget_password_email_otp: forget_password_email_otp_endpoint(config),
          reset_password_email_otp: reset_password_email_otp_endpoint(config)
        },
        hooks: {
          after: [
            {
              matcher: ->(ctx) { ctx.path.to_s.start_with?("/sign-up") && config[:send_verification_on_sign_up] && !config[:override_default_email_verification] },
              handler: ->(ctx) { email_otp_after_sign_up(ctx, config) }
            }
          ]
        },
        rate_limit: email_otp_rate_limits,
        error_codes: EMAIL_OTP_ERROR_CODES,
        options: config
      )
    end

    def email_otp_init(config)
      lambda do |context|
        next unless config[:override_default_email_verification]

        {
          options: {
            email_verification: {
              send_verification_email: lambda do |data, request = nil|
                user = fetch_value(data, :user) || data
                email = fetch_value(user, :email).to_s
                endpoint_context = Endpoint::Context.new(
                  path: "/send-verification-email",
                  method: "POST",
                  query: {},
                  body: {"email" => email, "type" => "email-verification"},
                  params: {},
                  headers: {},
                  context: context,
                  request: request
                )
                email_otp_send_verification(endpoint_context, config, email: email, type: "email-verification")
              end
            }
          }
        }
      end
    end

    def send_verification_otp_endpoint(config)
      Endpoint.new(path: "/email-otp/send-verification-otp", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        email = body[:email].to_s.downcase
        type = body[:type].to_s
        validate_email_otp_type!(type)
        validate_email_otp_email!(email)

        sender = config[:send_verification_otp]
        unless sender.respond_to?(:call)
          raise APIError.new("BAD_REQUEST", message: "send email verification is not implemented")
        end

        email_otp_send_verification(ctx, config, email: email, type: type)
        ctx.json({success: true})
      end
    end

    def create_verification_otp_endpoint(config)
      Endpoint.new(method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        email = body[:email].to_s.downcase
        type = body[:type].to_s
        validate_email_otp_type!(type)

        otp = email_otp_generate(config, email: email, type: type, ctx: ctx)
        email_otp_store(ctx, config, email: email, type: type, otp: otp)
        otp
      end
    end

    def get_verification_otp_endpoint(config)
      Endpoint.new(path: "/email-otp/get-verification-otp", method: "GET") do |ctx|
        query = normalize_hash(ctx.query)
        email = query[:email].to_s.downcase
        type = query[:type].to_s
        validate_email_otp_type!(type)
        verification = ctx.context.internal_adapter.find_verification_value(email_otp_identifier(email, type))
        next ctx.json({otp: nil}) unless verification && !Routes.expired_time?(verification["expiresAt"])

        stored_otp, = email_otp_split(verification["value"])
        case config[:store_otp].to_s
        when "hashed"
          raise APIError.new("BAD_REQUEST", message: "OTP is hashed, cannot return the plain text OTP")
        when "encrypted"
          next ctx.json({otp: Crypto.symmetric_decrypt(key: ctx.context.secret, data: stored_otp)})
        end

        storage = config[:store_otp]
        if storage.is_a?(Hash) && storage[:hash].respond_to?(:call)
          raise APIError.new("BAD_REQUEST", message: "OTP is hashed, cannot return the plain text OTP")
        elsif storage.is_a?(Hash) && storage[:decrypt].respond_to?(:call)
          next ctx.json({otp: storage[:decrypt].call(stored_otp)})
        end

        ctx.json({otp: stored_otp})
      end
    end

    def check_verification_otp_endpoint(config)
      Endpoint.new(path: "/email-otp/check-verification-otp", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        email = body[:email].to_s.downcase
        type = body[:type].to_s
        otp = body[:otp].to_s
        validate_email_otp_type!(type)
        validate_email_otp_email!(email)
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["USER_NOT_FOUND"]) unless ctx.context.internal_adapter.find_user_by_email(email)

        email_otp_verify!(ctx, config, email: email, type: type, otp: otp, consume: false)
        ctx.json({success: true})
      end
    end

    def verify_email_otp_endpoint(config)
      Endpoint.new(path: "/email-otp/verify-email", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        email = body[:email].to_s.downcase
        otp = body[:otp].to_s
        validate_email_otp_email!(email)

        email_otp_verify!(ctx, config, email: email, type: "email-verification", otp: otp)
        found = ctx.context.internal_adapter.find_user_by_email(email)
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["USER_NOT_FOUND"]) unless found

        user = found[:user]
        call_email_verification_option(ctx, :before_email_verification, user)
        updated = ctx.context.internal_adapter.update_user(user["id"], email: email, emailVerified: true)
        call_email_verification_option(ctx, :on_email_verification, updated)
        call_email_verification_option(ctx, :after_email_verification, updated)

        if ctx.context.options.email_verification[:auto_sign_in_after_verification]
          session = ctx.context.internal_adapter.create_session(updated["id"])
          Cookies.set_session_cookie(ctx, {session: session, user: updated})
          next ctx.json({status: true, token: session["token"], user: Schema.parse_output(ctx.context.options, "user", updated)})
        end

        current = Routes.current_session(ctx, allow_nil: true)
        Cookies.set_session_cookie(ctx, {session: current[:session], user: updated}) if current
        ctx.json({status: true, token: nil, user: Schema.parse_output(ctx.context.options, "user", updated)})
      end
    end

    def sign_in_email_otp_endpoint(config)
      Endpoint.new(path: "/sign-in/email-otp", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        email = body[:email].to_s.downcase
        otp = body[:otp].to_s

        email_otp_verify!(ctx, config, email: email, type: "sign-in", otp: otp)
        found = ctx.context.internal_adapter.find_user_by_email(email)
        user = if found
          found[:user]
        else
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["USER_NOT_FOUND"]) if config[:disable_sign_up]

          ctx.context.internal_adapter.create_user(email: email, emailVerified: true, name: "")
        end

        unless user["emailVerified"]
          user = ctx.context.internal_adapter.update_user(user["id"], emailVerified: true)
        end

        session = ctx.context.internal_adapter.create_session(user["id"])
        Cookies.set_session_cookie(ctx, {session: session, user: user})
        ctx.json({token: session["token"], user: Schema.parse_output(ctx.context.options, "user", user)})
      end
    end

    def request_password_reset_email_otp_endpoint(config)
      Endpoint.new(path: "/email-otp/request-password-reset", method: "POST") do |ctx|
        email_otp_password_reset_request(ctx, config)
      end
    end

    def forget_password_email_otp_endpoint(config)
      Endpoint.new(path: "/forget-password/email-otp", method: "POST") do |ctx|
        email_otp_password_reset_request(ctx, config)
      end
    end

    def reset_password_email_otp_endpoint(config)
      Endpoint.new(path: "/email-otp/reset-password", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        email = body[:email].to_s.downcase
        otp = body[:otp].to_s
        password = body[:password].to_s

        email_otp_verify!(ctx, config, email: email, type: "forget-password", otp: otp)
        found = ctx.context.internal_adapter.find_user_by_email(email, include_accounts: true)
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["USER_NOT_FOUND"]) unless found

        Routes.validate_password_length!(password, ctx.context.options.email_and_password)
        hashed = Routes.hash_password(ctx, password)
        account = found[:accounts].find { |entry| entry["providerId"] == "credential" }
        if account
          ctx.context.internal_adapter.update_password(found[:user]["id"], hashed)
        else
          ctx.context.internal_adapter.create_account(userId: found[:user]["id"], providerId: "credential", accountId: found[:user]["id"], password: hashed)
        end

        ctx.context.internal_adapter.update_user(found[:user]["id"], emailVerified: true) unless found[:user]["emailVerified"]
        callback = ctx.context.options.email_and_password[:on_password_reset]
        callback.call({user: found[:user]}, ctx.request) if callback.respond_to?(:call)
        ctx.context.internal_adapter.delete_sessions(found[:user]["id"]) if ctx.context.options.email_and_password[:revoke_sessions_on_password_reset]
        ctx.json({success: true})
      end
    end

    def email_otp_after_sign_up(ctx, config)
      response = ctx.returned
      user = fetch_value(response, :user)
      email = fetch_value(user, :email).to_s.downcase
      return unless Routes::EMAIL_PATTERN.match?(email)

      otp = email_otp_generate(config, email: email, type: "email-verification", ctx: ctx)
      email_otp_store(ctx, config, email: email, type: "email-verification", otp: otp)
      email_otp_deliver(config, {email: email, otp: otp, type: "email-verification"}, ctx)
      nil
    end

    def email_otp_password_reset_request(ctx, config)
      body = normalize_hash(ctx.body)
      email = body[:email].to_s.downcase
      otp = email_otp_generate(config, email: email, type: "forget-password", ctx: ctx)
      email_otp_store(ctx, config, email: email, type: "forget-password", otp: otp)

      found = ctx.context.internal_adapter.find_user_by_email(email)
      unless found
        ctx.context.internal_adapter.delete_verification_by_identifier(email_otp_identifier(email, "forget-password"))
        return ctx.json({success: true})
      end

      email_otp_deliver(config, {email: email, otp: otp, type: "forget-password"}, ctx)
      ctx.json({success: true})
    end

    def email_otp_send_verification(ctx, config, email:, type:)
      otp = email_otp_generate(config, email: email, type: type, ctx: ctx)
      email_otp_store(ctx, config, email: email, type: type, otp: otp)
      found = ctx.context.internal_adapter.find_user_by_email(email)

      unless found
        if type == "sign-in" && !config[:disable_sign_up]
          # Upstream allows sign-in OTP creation for new users when sign-up is enabled.
        else
          ctx.context.internal_adapter.delete_verification_by_identifier(email_otp_identifier(email, type))
          return
        end
      end

      email_otp_deliver(config, {email: email, otp: otp, type: type}, ctx)
    end

    def email_otp_store(ctx, config, email:, type:, otp:)
      stored = email_otp_stored_value(ctx, config, otp)
      identifier = email_otp_identifier(email, type)
      ctx.context.internal_adapter.delete_verification_by_identifier(identifier)
      ctx.context.internal_adapter.create_verification_value(
        identifier: identifier,
        value: "#{stored}:0",
        expiresAt: Time.now + config[:expires_in].to_i
      )
    end

    def email_otp_verify!(ctx, config, email:, type:, otp:, consume: true)
      verification = ctx.context.internal_adapter.find_verification_value(email_otp_identifier(email, type))
      raise APIError.new("BAD_REQUEST", message: EMAIL_OTP_ERROR_CODES["INVALID_OTP"]) unless verification

      if Routes.expired_time?(verification["expiresAt"])
        ctx.context.internal_adapter.delete_verification_value(verification["id"])
        raise APIError.new("BAD_REQUEST", message: EMAIL_OTP_ERROR_CODES["OTP_EXPIRED"])
      end

      otp_value, attempts = email_otp_split(verification["value"])
      attempts_count = attempts.to_i
      if attempts_count >= config[:allowed_attempts].to_i
        ctx.context.internal_adapter.delete_verification_value(verification["id"])
        raise APIError.new("FORBIDDEN", message: EMAIL_OTP_ERROR_CODES["TOO_MANY_ATTEMPTS"])
      end

      unless email_otp_matches?(ctx, config, otp_value, otp)
        ctx.context.internal_adapter.update_verification_value(verification["id"], value: "#{otp_value}:#{attempts_count + 1}")
        raise APIError.new("BAD_REQUEST", message: EMAIL_OTP_ERROR_CODES["INVALID_OTP"])
      end

      ctx.context.internal_adapter.delete_verification_value(verification["id"]) if consume
      true
    end

    def email_otp_generate(config, email:, type:, ctx:)
      generator = config[:generate_otp]
      generated = generator.call({email: email, type: type}, ctx) if generator.respond_to?(:call)
      return generated.to_s if generated && !generated.to_s.empty?

      Array.new(config[:otp_length].to_i) { SecureRandom.random_number(10).to_s }.join
    end

    def email_otp_stored_value(ctx, config, otp)
      storage = config[:store_otp]
      return Crypto.sha256(otp, encoding: :base64url) if storage.to_s == "hashed"
      return Crypto.symmetric_encrypt(key: ctx.context.secret, data: otp) if storage.to_s == "encrypted"

      if storage.is_a?(Hash)
        return storage[:hash].call(otp) if storage[:hash].respond_to?(:call)
        return storage[:encrypt].call(otp) if storage[:encrypt].respond_to?(:call)
      end

      otp
    end

    def email_otp_matches?(ctx, config, stored_otp, otp)
      storage = config[:store_otp]
      actual, expected = if storage.to_s == "hashed"
        [Crypto.sha256(otp, encoding: :base64url), stored_otp]
      elsif storage.to_s == "encrypted"
        [Crypto.symmetric_decrypt(key: ctx.context.secret, data: stored_otp), otp]
      elsif storage.is_a?(Hash) && storage[:hash].respond_to?(:call)
        [storage[:hash].call(otp), stored_otp]
      elsif storage.is_a?(Hash) && storage[:decrypt].respond_to?(:call)
        [storage[:decrypt].call(stored_otp), otp]
      else
        [otp, stored_otp]
      end
      return false unless actual
      return false unless actual.to_s.bytesize == expected.to_s.bytesize

      Crypto.constant_time_compare(actual.to_s, expected.to_s)
    end

    def email_otp_deliver(config, data, ctx)
      sender = config[:send_verification_otp]
      sender.call(data, ctx) if sender.respond_to?(:call)
    end

    def email_otp_identifier(email, type)
      "#{type}-otp-#{email}"
    end

    def email_otp_split(value)
      string = value.to_s
      index = string.rindex(":")
      return [string, ""] unless index

      [string[0...index], string[(index + 1)..]]
    end

    def validate_email_otp_email!(email)
      raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_EMAIL"]) unless Routes::EMAIL_PATTERN.match?(email)
    end

    def validate_email_otp_type!(type)
      return if %w[email-verification sign-in forget-password].include?(type)

      raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VALIDATION_ERROR"])
    end

    def call_email_verification_option(ctx, key, user)
      callback = ctx.context.options.email_verification[key]
      callback.call(user, ctx.request) if callback.respond_to?(:call)
    end

    def email_otp_rate_limits
      %w[
        /email-otp/send-verification-otp
        /email-otp/check-verification-otp
        /email-otp/verify-email
        /sign-in/email-otp
        /email-otp/request-password-reset
        /email-otp/reset-password
        /forget-password/email-otp
      ].map do |path|
        {
          path_matcher: ->(request_path) { request_path == path },
          window: 60,
          max: 3
        }
      end
    end
  end
end
