# frozen_string_literal: true

module BetterAuth
  module SSO
    module SAML
      module Algorithms
        module_function

        SignatureAlgorithm = BetterAuth::Plugins::SSO_SAML_SIGNATURE_ALGORITHMS
        DigestAlgorithm = BetterAuth::Plugins::SSO_SAML_DIGEST_ALGORITHMS
        SecureSignatureAlgorithms = BetterAuth::Plugins::SSO_SAML_SECURE_SIGNATURE_ALGORITHMS
        SecureDigestAlgorithms = BetterAuth::Plugins::SSO_SAML_SECURE_DIGEST_ALGORITHMS

        def validate(xml, **options)
          BetterAuth::Plugins.sso_validate_saml_algorithms!(xml, options)
        end

        def normalize_signature(algorithm)
          BetterAuth::Plugins.sso_normalize_saml_signature_algorithm(algorithm)
        end

        def normalize_digest(algorithm)
          BetterAuth::Plugins.sso_normalize_saml_digest_algorithm(algorithm)
        end
      end
    end
  end
end
