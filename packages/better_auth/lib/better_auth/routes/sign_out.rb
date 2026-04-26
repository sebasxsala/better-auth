# frozen_string_literal: true

module BetterAuth
  module Routes
    def self.sign_out
      Endpoint.new(path: "/sign-out", method: "POST") do |ctx|
        token_cookie = ctx.context.auth_cookies[:session_token]
        token = ctx.get_signed_cookie(token_cookie.name, ctx.context.secret)
        ctx.context.internal_adapter.delete_session(token) if token
        Cookies.delete_session_cookie(ctx)
        ctx.json({success: true})
      end
    end
  end
end
