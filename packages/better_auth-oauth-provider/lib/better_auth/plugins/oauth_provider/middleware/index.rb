# frozen_string_literal: true

module BetterAuth
  module Plugins
    module OAuthProvider
      module Middleware
        module_function

        def public_session_middleware(options)
          lambda do |ctx|
            unless options[:allow_public_client_prelogin] || options[:allowPublicClientPrelogin]
              raise APIError.new("BAD_REQUEST")
            end

            body = OAuthProtocol.stringify_keys(ctx.body || {})
            valid = Utils.verify_oauth_query_params(body["oauth_query"], ctx.context.secret)
            raise APIError.new("UNAUTHORIZED", body: {error: "invalid_signature"}) unless valid

            true
          end
        end
      end
    end
  end
end
