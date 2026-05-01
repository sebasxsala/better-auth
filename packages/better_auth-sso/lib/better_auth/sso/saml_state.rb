# frozen_string_literal: true

module BetterAuth
  module SSO
    module SAMLState
      module_function

      def generate_relay_state(ctx, additional_data = {})
        callback_url = BetterAuth::Plugins.sso_fetch(ctx.body, :callback_url)
        raise APIError.new("BAD_REQUEST", message: "callbackURL is required") if callback_url.to_s.empty?

        BetterAuth::Crypto.sign_jwt(
          (additional_data || {}).merge(
            callbackURL: callback_url,
            codeVerifier: BetterAuth::Crypto.random_string(128),
            errorURL: BetterAuth::Plugins.sso_fetch(ctx.body, :error_callback_url),
            newUserURL: BetterAuth::Plugins.sso_fetch(ctx.body, :new_user_callback_url),
            requestSignUp: BetterAuth::Plugins.sso_fetch(ctx.body, :request_sign_up),
            expiresAt: ((Time.now.to_f * 1000).to_i + (10 * 60 * 1000))
          ),
          ctx.context.secret,
          expires_in: 600
        )
      end

      def parse_relay_state(ctx)
        BetterAuth::Plugins.sso_verify_state(BetterAuth::Plugins.sso_fetch(ctx.body, :relay_state), ctx.context.secret)
      end
    end
  end
end
