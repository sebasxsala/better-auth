# frozen_string_literal: true

module BetterAuth
  module SSO
    module Routes
      module SSO
        module_function

        def oidc_redirect_uri(context, provider_id)
          BetterAuth::Plugins.sso_oidc_redirect_uri(context, provider_id)
        end

        def saml_authorization_url(provider, relay_state, ctx = nil, config = {})
          BetterAuth::Plugins.sso_saml_authorization_url(provider, relay_state, ctx, config)
        end
      end
    end
  end
end
