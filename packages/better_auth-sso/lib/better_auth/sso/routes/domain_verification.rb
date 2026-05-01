# frozen_string_literal: true

module BetterAuth
  module SSO
    module Routes
      module DomainVerification
        module_function

        def identifier(config, provider_id)
          BetterAuth::Plugins.sso_domain_verification_identifier(config, provider_id)
        end

        def hostname(domain)
          BetterAuth::Plugins.sso_hostname_from_domain(domain)
        end
      end
    end
  end
end
