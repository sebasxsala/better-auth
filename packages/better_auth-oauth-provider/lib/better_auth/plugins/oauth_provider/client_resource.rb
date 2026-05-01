# frozen_string_literal: true

module BetterAuth
  module Plugins
    module OAuthProvider
      module ClientResource
        ID = "oauth-provider-resource-client"

        module_function

        def protected_resource_metadata(overrides = {}, authorization_server: nil, oauth_provider_options: nil, external_scopes: [])
          data = OAuthProtocol.stringify_keys(overrides || {})
          resource = data["resource"] || authorization_server
          raise Error, "missing required resource" if resource.to_s.empty?

          validate_resource_scopes!(data["scopes_supported"], oauth_provider_options, external_scopes)

          response = {resource: resource}
          response[:authorization_servers] = [authorization_server] if authorization_server
          response.merge!(data.transform_keys(&:to_sym))
          response[:resource] = resource
          response
        end

        def validate_resource_scopes!(scopes_supported, oauth_provider_options, external_scopes)
          scopes = OAuthProtocol.parse_scopes(scopes_supported)
          return if scopes.empty?

          allowed = OAuthProtocol.parse_scopes(oauth_provider_options && oauth_provider_options[:scopes]) + OAuthProtocol.parse_scopes(external_scopes)
          scopes.each do |scope|
            if scope == "openid"
              raise Error, "Only the Auth Server should utilize the openid scope"
            end
            next if allowed.empty? || allowed.include?(scope)

            raise Error, %(Unsupported scope #{scope}. If external, please add to "externalScopes")
          end
        end
      end
    end
  end
end
