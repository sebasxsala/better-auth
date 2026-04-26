# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def bearer(options = {})
      config = normalize_hash(options)

      Plugin.new(
        id: "bearer",
        hooks: {
          before: [
            {
              matcher: ->(ctx) { authorization_header(ctx) },
              handler: ->(ctx) { apply_bearer_token(ctx, config) }
            }
          ],
          after: [
            {
              matcher: ->(_ctx) { true },
              handler: ->(ctx) { expose_auth_token(ctx) }
            }
          ]
        },
        options: config
      )
    end

    def authorization_header(ctx)
      ctx.headers["authorization"] || ctx.headers["Authorization"]
    end

    def apply_bearer_token(ctx, config)
      token = authorization_header(ctx).to_s.sub(/\ABearer\s+/i, "")
      return if token.empty?

      signed_token = token.include?(".") ? token : sign_bearer_token(ctx, token, config)
      return unless signed_token && valid_signed_token?(ctx, signed_token)

      cookie_name = ctx.context.auth_cookies[:session_token].name
      cookie = [ctx.headers["cookie"], "#{cookie_name}=#{signed_token}"].compact.reject(&:empty?).join("; ")
      {context: {headers: ctx.headers.merge("cookie" => cookie)}}
    end

    def sign_bearer_token(ctx, token, config)
      return if config[:require_signature]

      signature = Crypto.hmac_signature(token, ctx.context.secret, encoding: :base64url)
      "#{token}.#{signature}"
    end

    def valid_signed_token?(ctx, signed_token)
      payload, signature = signed_token.rpartition(".").values_at(0, 2)
      return false if payload.empty? || signature.empty?

      Crypto.verify_hmac_signature(payload, signature, ctx.context.secret, encoding: :base64url)
    end

    def expose_auth_token(ctx)
      set_cookie = ctx.response_headers["set-cookie"].to_s
      token_name = ctx.context.auth_cookies[:session_token].name
      token = set_cookie.lines.filter_map do |line|
        cookie = line.split(";").first
        name, value = cookie.split("=", 2)
        value if name == token_name && value && !value.empty?
      end.first
      return unless token

      exposed = ctx.response_headers["access-control-expose-headers"].to_s.split(",").map(&:strip).reject(&:empty?)
      exposed << "set-auth-token"
      ctx.set_header("set-auth-token", token)
      ctx.set_header("access-control-expose-headers", exposed.uniq.join(", "))
      nil
    end
  end
end
