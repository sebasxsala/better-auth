# frozen_string_literal: true

require "securerandom"
require "uri"

module BetterAuth
  module Routes
    PASSWORD_RESET_MESSAGE = "If this email exists in our system, check your email for the reset link"

    def self.request_password_reset
      Endpoint.new(path: "/request-password-reset", method: "POST") do |ctx|
        sender = ctx.context.options.email_and_password[:send_reset_password]
        raise APIError.new("BAD_REQUEST", message: "Reset password isn't enabled") unless sender.respond_to?(:call)

        body = normalize_hash(ctx.body)
        email = body["email"].to_s.downcase
        found = ctx.context.internal_adapter.find_user_by_email(email, include_accounts: true)
        unless found
          SecureRandom.hex(12)
          ctx.context.internal_adapter.find_verification_value("dummy-verification-token")
          next ctx.json({status: true, message: PASSWORD_RESET_MESSAGE})
        end

        token = SecureRandom.hex(12)
        expires_in = ctx.context.options.email_and_password[:reset_password_token_expires_in] || 3600
        ctx.context.internal_adapter.create_verification_value(
          identifier: "reset-password:#{token}",
          value: found[:user]["id"],
          expiresAt: Time.now + expires_in.to_i
        )

        redirect_to = body["redirectTo"] || body["redirect_to"]
        callback = redirect_to ? URI.encode_www_form_component(redirect_to) : ""
        url = "#{ctx.context.base_url}/reset-password/#{token}?callbackURL=#{callback}"
        sender.call({user: found[:user], url: url, token: token}, ctx.request)
        ctx.json({status: true, message: PASSWORD_RESET_MESSAGE})
      end
    end

    def self.request_password_reset_callback
      Endpoint.new(path: "/reset-password/:token", method: "GET") do |ctx|
        token = ctx.params[:token].to_s
        callback_url = fetch_value(ctx.query, "callbackURL") || "/error"
        verification = ctx.context.internal_adapter.find_verification_value("reset-password:#{token}")

        unless verification && !expired_time?(verification["expiresAt"])
          raise ctx.redirect(absolute_callback(ctx.context, callback_url, error: "INVALID_TOKEN"))
        end

        raise ctx.redirect(absolute_callback(ctx.context, callback_url, token: token))
      end
    end

    def self.reset_password
      Endpoint.new(path: "/reset-password", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        token = body["token"] || fetch_value(ctx.query, "token")
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_TOKEN"]) if token.to_s.empty?

        password = body["newPassword"] || body["new_password"]
        validate_password_length!(password, ctx.context.options.email_and_password)

        verification = ctx.context.internal_adapter.find_verification_value("reset-password:#{token}")
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_TOKEN"]) unless verification && !expired_time?(verification["expiresAt"])

        user_id = verification["value"]
        hashed = hash_password(ctx, password)
        account = ctx.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "credential" }
        if account
          ctx.context.internal_adapter.update_password(user_id, hashed)
        else
          ctx.context.internal_adapter.create_account(userId: user_id, providerId: "credential", accountId: user_id, password: hashed)
        end
        ctx.context.internal_adapter.delete_verification_value(verification["id"])

        if (callback = ctx.context.options.email_and_password[:on_password_reset])
          user = ctx.context.internal_adapter.find_user_by_id(user_id)
          callback.call({user: user}, ctx.request) if user
        end
        ctx.context.internal_adapter.delete_sessions(user_id) if ctx.context.options.email_and_password[:revoke_sessions_on_password_reset]

        ctx.json({status: true})
      end
    end

    def self.verify_password
      Endpoint.new(path: "/verify-password", method: "POST") do |ctx|
        session = current_session(ctx, sensitive: true)
        password = normalize_hash(ctx.body)["password"].to_s
        account = credential_account(ctx, session[:user]["id"])
        valid = account && account["password"] && verify_password_value(ctx, password, account["password"])
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_PASSWORD"]) unless valid

        ctx.json({status: true})
      end
    end

    def self.validate_password_length!(password, email_config)
      unless password.is_a?(String) && !password.empty?
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_PASSWORD"])
      end
      raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["PASSWORD_TOO_SHORT"]) if password.length < email_config[:min_password_length].to_i
      raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["PASSWORD_TOO_LONG"]) if password.length > email_config[:max_password_length].to_i
    end

    def self.hash_password(ctx, password)
      Password.hash(
        password,
        hasher: ctx.context.options.email_and_password.dig(:password, :hash),
        algorithm: ctx.context.options.password_hasher
      )
    end

    def self.verify_password_value(ctx, password, digest)
      Password.verify(
        password: password,
        hash: digest,
        verifier: ctx.context.options.email_and_password.dig(:password, :verify),
        algorithm: ctx.context.options.password_hasher
      )
    end

    def self.credential_account(ctx, user_id)
      ctx.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "credential" }
    end

    def self.expired_time?(value)
      value && value < Time.now
    end

    def self.fetch_value(hash, key)
      snake_key = key.to_s
        .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
        .tr("-", "_")
        .downcase
      hash[key] ||
        hash[key.to_s] ||
        hash[key.to_sym] ||
        hash[Schema.storage_key(key)] ||
        hash[Schema.storage_key(key).to_sym] ||
        hash[snake_key] ||
        hash[snake_key.to_sym]
    end

    def self.absolute_callback(context, callback_url, params)
      uri = URI.parse(callback_url.to_s)
      origin = Configuration.origin_for(URI.parse(context.base_url))
      url = uri.relative? ? URI.join("#{origin}/", callback_url.to_s.delete_prefix("/")) : uri
      query = URI.decode_www_form(url.query.to_s)
      params.each { |key, value| query << [key.to_s, value] }
      url.query = URI.encode_www_form(query)
      url.to_s
    end
  end
end
