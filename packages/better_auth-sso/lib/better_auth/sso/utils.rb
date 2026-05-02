# frozen_string_literal: true

require "json"
require "openssl"

module BetterAuth
  module SSO
    module Utils
      module_function

      def safe_json_parse(value)
        return nil if value.nil? || value == ""
        return value if value.is_a?(Hash) || value.is_a?(Array)

        JSON.parse(value.to_s)
      rescue JSON::ParserError => error
        raise Error, "Failed to parse JSON: #{error.message}"
      end

      def domain_matches?(search_domain, domain_list)
        BetterAuth::Plugins.sso_email_domain_matches?(search_domain, domain_list)
      end

      def validate_email_domain(email, domain)
        BetterAuth::Plugins.sso_email_domain_matches?(email, domain)
      end

      def parse_certificate(cert)
        value = cert.to_s
        normalized = if value.include?("-----BEGIN")
          value
        else
          body = value.delete("\n\r\t ")
          "-----BEGIN CERTIFICATE-----\n#{body.scan(/.{1,64}/).join("\n")}\n-----END CERTIFICATE-----"
        end
        certificate = OpenSSL::X509::Certificate.new(normalized)
        fingerprint = OpenSSL::Digest::SHA256.hexdigest(certificate.to_der).upcase.scan(/../).join(":")
        {
          fingerprint_sha256: fingerprint,
          not_before: certificate.not_before,
          not_after: certificate.not_after,
          public_key_algorithm: certificate.public_key.class.name.split("::").last.upcase
        }
      end

      def hostname_from_domain(domain)
        BetterAuth::Plugins.sso_hostname_from_domain(domain)
      end

      def mask_client_id(client_id)
        BetterAuth::Plugins.sso_mask_client_id(client_id)
      end
    end
  end
end
