# frozen_string_literal: true

module BetterAuth
  module SSO
    module Client
      ID = "sso-client"
      PATH_METHODS = {
        "/sso/providers" => "GET",
        "/sso/get-provider" => "GET"
      }.freeze

      module_function

      def sso_client(options = {})
        domain_verification = options[:domain_verification] || options["domainVerification"] || options["domain_verification"] || {}
        enabled = domain_verification[:enabled] || domain_verification["enabled"] || false

        {
          id: ID,
          version: VERSION,
          infer_server_plugin: {
            domain_verification: {
              enabled: !!enabled
            }
          },
          path_methods: PATH_METHODS
        }
      end
    end
  end
end
