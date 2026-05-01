# frozen_string_literal: true

module BetterAuth
  module SSO
    module Routes
      module Helpers
        module_function

        def find_saml_provider!(ctx, provider_id)
          BetterAuth::Plugins.sso_find_provider!(ctx, provider_id)
        end

        def create_saml_post_form(action, saml_param, saml_value, relay_state = nil)
          BetterAuth::Plugins.sso_saml_post_form(action, saml_param, saml_value, relay_state)
        end
      end
    end
  end
end
