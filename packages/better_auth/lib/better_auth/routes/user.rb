# frozen_string_literal: true

module BetterAuth
  module Routes
    def self.update_user
      Endpoint.new(path: "/update-user", method: "POST") do |ctx|
        session = current_session(ctx)
        body = normalize_hash(ctx.body)
        raise APIError.new("BAD_REQUEST", message: "Body must be an object") unless body.is_a?(Hash)
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["EMAIL_CAN_NOT_BE_UPDATED"]) if body.key?("email")
        raise APIError.new("BAD_REQUEST", message: "No fields to update") if body.empty?

        ctx.context.internal_adapter.update_user(session[:user]["id"], body)
        ctx.json({status: true})
      end
    end

    def self.change_password
      Endpoint.new(path: "/change-password", method: "POST") do |ctx|
        session = current_session(ctx, sensitive: true)
        body = normalize_hash(ctx.body)
        new_password = body["newPassword"] || body["new_password"]
        current_password = body["currentPassword"] || body["current_password"]
        validate_password_length!(new_password, ctx.context.options.email_and_password)
        account = credential_account(ctx, session[:user]["id"])
        unless account && account["password"] && verify_password_value(ctx, current_password.to_s, account["password"])
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_PASSWORD"])
        end

        ctx.context.internal_adapter.update_account(account["id"], password: hash_password(ctx, new_password))
        token = nil
        if body["revokeOtherSessions"] || body["revoke_other_sessions"]
          ctx.context.internal_adapter.delete_sessions(session[:user]["id"])
          new_session = ctx.context.internal_adapter.create_session(session[:user]["id"])
          Cookies.set_session_cookie(ctx, {session: new_session, user: session[:user]})
          token = new_session["token"]
        end
        ctx.json({token: token, user: Schema.parse_output(ctx.context.options, "user", session[:user])})
      end
    end

    def self.set_password
      Endpoint.new(path: "/set-password", method: "POST") do |ctx|
        session = current_session(ctx, sensitive: true)
        body = normalize_hash(ctx.body)
        new_password = body["newPassword"] || body["new_password"]
        validate_password_length!(new_password, ctx.context.options.email_and_password)
        account = credential_account(ctx, session[:user]["id"])
        raise APIError.new("BAD_REQUEST", message: "user already has a password") if account && account["password"]

        ctx.context.internal_adapter.link_account(
          userId: session[:user]["id"],
          providerId: "credential",
          accountId: session[:user]["id"],
          password: hash_password(ctx, new_password)
        )
        ctx.json({status: true})
      end
    end

    def self.delete_user
      Endpoint.new(path: "/delete-user", method: "POST") do |ctx|
        enabled = ctx.context.options.user.dig(:delete_user, :enabled)
        raise APIError.new("NOT_FOUND") unless enabled

        session = current_session(ctx, sensitive: true)
        body = normalize_hash(ctx.body)
        if body["password"]
          account = credential_account(ctx, session[:user]["id"])
          unless account && account["password"] && verify_password_value(ctx, body["password"], account["password"])
            raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_PASSWORD"])
          end
        end

        if body["token"]
          delete_user_by_token!(ctx, session, body["token"])
        elsif (sender = ctx.context.options.user.dig(:delete_user, :send_delete_account_verification))
          token = SecureRandom.hex(16)
          ctx.context.internal_adapter.create_verification_value(
            identifier: "delete-account-#{token}",
            value: session[:user]["id"],
            expiresAt: Time.now + ctx.context.options.user.dig(:delete_user, :delete_token_expires_in).to_i
          )
          sender.call({user: session[:user], token: token}, ctx.request)
          next ctx.json({success: true, message: "Verification email sent"})
        end

        delete_current_user!(ctx, session)
        ctx.json({success: true, message: "User deleted"})
      end
    end

    def self.delete_user_callback
      Endpoint.new(path: "/delete-user/callback", method: "GET") do |ctx|
        enabled = ctx.context.options.user.dig(:delete_user, :enabled)
        raise APIError.new("NOT_FOUND") unless enabled
        session = current_session(ctx)
        token = fetch_value(ctx.query, "token")
        delete_user_by_token!(ctx, session, token)
        delete_current_user!(ctx, session)
        callback_url = fetch_value(ctx.query, "callbackURL")
        raise ctx.redirect(callback_url) if callback_url

        ctx.json({success: true, message: "User deleted"})
      end
    end

    def self.change_email
      Endpoint.new(path: "/change-email", method: "POST") do |ctx|
        enabled = ctx.context.options.user.dig(:change_email, :enabled)
        raise APIError.new("BAD_REQUEST", message: "Change email is disabled") unless enabled
        session = current_session(ctx, sensitive: true)
        body = normalize_hash(ctx.body)
        new_email = (body["newEmail"] || body["new_email"]).to_s.downcase
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["INVALID_EMAIL"]) unless EMAIL_PATTERN.match?(new_email)
        raise APIError.new("BAD_REQUEST", message: "Email is the same") if new_email == session[:user]["email"]
        raise APIError.new("UNPROCESSABLE_ENTITY", message: BASE_ERROR_CODES["USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"]) if ctx.context.internal_adapter.find_user_by_email(new_email)

        if !session[:user]["emailVerified"] && ctx.context.options.user.dig(:change_email, :update_email_without_verification)
          updated = ctx.context.internal_adapter.update_user_by_email(session[:user]["email"], email: new_email)
          Cookies.set_session_cookie(ctx, {session: session[:session], user: updated})
          next ctx.json({status: true})
        end

        sender = ctx.context.options.email_verification[:send_verification_email]
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VERIFICATION_EMAIL_NOT_ENABLED"]) unless sender.respond_to?(:call)

        token = create_email_verification_token(ctx, session[:user]["email"], update_to: new_email, extra: {"requestType" => "change-email-verification"})
        sender.call({user: session[:user].merge("email" => new_email), token: token}, ctx.request)
        ctx.json({status: true})
      end
    end

    def self.delete_user_by_token!(ctx, session, token)
      verification = ctx.context.internal_adapter.find_verification_value("delete-account-#{token}")
      unless verification && verification["value"] == session[:user]["id"] && !expired_time?(verification["expiresAt"])
        raise APIError.new("NOT_FOUND", message: BASE_ERROR_CODES["INVALID_TOKEN"])
      end
      ctx.context.internal_adapter.delete_verification_value(verification["id"])
    end

    def self.delete_current_user!(ctx, session)
      config = ctx.context.options.user[:delete_user] || {}
      call_option(config[:before_delete], session[:user], ctx.request)
      ctx.context.internal_adapter.delete_user(session[:user]["id"])
      ctx.context.internal_adapter.delete_sessions(session[:user]["id"])
      Cookies.delete_session_cookie(ctx)
      call_option(config[:after_delete], session[:user], ctx.request)
    end
  end
end
