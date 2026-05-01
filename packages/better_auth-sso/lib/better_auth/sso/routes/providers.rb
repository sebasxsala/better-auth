# frozen_string_literal: true

module BetterAuth
  module SSO
    module Routes
      module Providers
        module_function

        def sanitize(provider, context)
          BetterAuth::Plugins.sso_sanitize_provider(provider, context)
        end

        def provider_access?(provider, user_id, ctx)
          BetterAuth::Plugins.sso_provider_access?(provider, user_id, ctx)
        end
      end
    end
  end
end
