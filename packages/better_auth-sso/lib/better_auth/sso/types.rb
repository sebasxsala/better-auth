# frozen_string_literal: true

module BetterAuth
  module SSO
    module Types
      PROVIDER_TYPES = %w[oidc saml].freeze
      OIDC_TOKEN_ENDPOINT_AUTH_METHODS = %w[client_secret_post client_secret_basic].freeze

      module_function

      def provider_type?(value)
        PROVIDER_TYPES.include?(value.to_s)
      end

      def oidc_token_endpoint_auth_method?(value)
        OIDC_TOKEN_ENDPOINT_AUTH_METHODS.include?(value.to_s)
      end
    end
  end
end
