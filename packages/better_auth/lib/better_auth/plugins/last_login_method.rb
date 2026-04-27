# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def last_login_method(options = {})
      config = {
        cookie_name: "better-auth.last_used_login_method",
        max_age: 60 * 60 * 24 * 30
      }.merge(normalize_hash(options))

      Plugin.new(
        id: "last-login-method",
        schema: last_login_method_schema(config),
        hooks: {
          after: [
            {
              matcher: ->(_ctx) { true },
              handler: ->(ctx) { apply_last_login_method(ctx, config) }
            }
          ]
        },
        options: config
      )
    end

    def last_login_method_schema(config)
      return {} unless config[:store_in_database]

      field_name = config.dig(:schema, :user, :last_login_method) || "last_loginMethod"
      {
        user: {
          fields: {
            lastLoginMethod: {
              type: "string",
              input: false,
              required: false,
              field_name: field_name
            }
          }
        }
      }
    end

    def apply_last_login_method(ctx, config)
      method = resolve_login_method(ctx, config)
      return unless method

      set_cookie = ctx.response_headers["set-cookie"].to_s
      return unless set_cookie.include?(ctx.context.auth_cookies[:session_token].name)

      attributes = ctx.context.auth_cookies[:session_token].attributes.merge(max_age: config[:max_age], http_only: false)
      ctx.set_cookie(config[:cookie_name], method, attributes)

      if config[:store_in_database] && ctx.context.new_session&.dig(:user, "id")
        updated = ctx.context.internal_adapter.update_user(ctx.context.new_session[:user]["id"], lastLoginMethod: method)
        ctx.context.new_session[:user].merge!(updated) if updated
      end
      nil
    end

    def resolve_login_method(ctx, config)
      custom = config[:custom_resolve_method]
      resolved = custom.call(ctx) if custom.respond_to?(:call)
      return resolved if resolved

      case ctx.path
      when "/sign-in/email", "/sign-up/email"
        "email"
      when "/callback/:providerId"
        fetch_value(ctx.params, "providerId")
      when "/oauth2/callback/:providerId"
        fetch_value(ctx.params, "providerId")
      else
        return Regexp.last_match(1) if ctx.path.to_s =~ %r{\A/callback/([^/]+)\z}
        return Regexp.last_match(1) if ctx.path.to_s =~ %r{\A/oauth2/callback/([^/]+)\z}
        return "siwe" if ctx.path.to_s.include?("siwe")
        return "passkey" if ctx.path.to_s.include?("/passkey/verify-authentication")

        nil
      end
    end
  end
end
