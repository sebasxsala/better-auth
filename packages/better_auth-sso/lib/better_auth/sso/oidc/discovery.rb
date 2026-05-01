# frozen_string_literal: true

module BetterAuth
  module SSO
    module OIDC
      module Discovery
        module_function

        REQUIRED_DISCOVERY_FIELDS = %i[issuer authorization_endpoint token_endpoint jwks_uri].freeze

        def compute_discovery_url(issuer)
          "#{issuer.to_s.sub(%r{/+\z}, "")}/.well-known/openid-configuration"
        end

        def discover_oidc_config(**kwargs)
          BetterAuth::Plugins.sso_discover_oidc_config(**kwargs)
        end

        def normalize_url(value, issuer, trusted_origin = nil)
          BetterAuth::Plugins.sso_normalize_discovery_url(value, issuer, trusted_origin)
        end

        def needs_runtime_discovery?(oidc_config)
          BetterAuth::Plugins.sso_oidc_needs_runtime_discovery?(oidc_config)
        end

        def select_token_endpoint_auth_method(existing_config = {}, methods = [])
          existing = BetterAuth::Plugins.normalize_hash(existing_config || {})
          return existing[:token_endpoint_authentication] if existing[:token_endpoint_authentication]
          return "client_secret_post" if Array(methods).include?("client_secret_post") && !Array(methods).include?("client_secret_basic")

          "client_secret_basic"
        end
      end
    end
  end
end
