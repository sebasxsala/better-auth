# frozen_string_literal: true

require "uri"

module BetterAuth
  module Plugins
    module MCP
      module_function

      def validate_issuer_url(value)
        uri = URI.parse(value.to_s)
        uri.query = nil
        uri.fragment = nil
        if uri.scheme == "http" && !["localhost", "127.0.0.1", "::1"].include?(uri.hostname || uri.host)
          uri.scheme = "https"
        end
        uri.to_s.sub(%r{/+\z}, "")
      rescue URI::InvalidURIError
        value.to_s.split(/[?#]/).first.sub(%r{/+\z}, "")
      end

      def oauth_metadata(ctx, config)
        base = OAuthProtocol.endpoint_base(ctx)
        {
          issuer: validate_issuer_url(OAuthProtocol.issuer(ctx)),
          authorization_endpoint: "#{base}/oauth2/authorize",
          token_endpoint: "#{base}/oauth2/token",
          userinfo_endpoint: "#{base}/oauth2/userinfo",
          registration_endpoint: "#{base}/oauth2/register",
          introspection_endpoint: "#{base}/oauth2/introspect",
          revocation_endpoint: "#{base}/oauth2/revoke",
          jwks_uri: mcp_jwks_uri(ctx, config),
          scopes_supported: config[:scopes],
          response_types_supported: ["code"],
          response_modes_supported: ["query"],
          grant_types_supported: config[:grant_types],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: mcp_signing_algs(ctx, config),
          token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
          introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: true,
          claims_supported: %w[sub iss aud exp iat sid scope azp email email_verified name picture family_name given_name]
        }.merge(BetterAuth::Plugins.normalize_hash(config.dig(:oidc_config, :metadata) || {}))
      end

      def protected_resource_metadata(ctx, config)
        base = OAuthProtocol.endpoint_base(ctx)
        origin = OAuthProtocol.origin_for(base)
        {
          resource: config[:resource] || origin,
          authorization_servers: [origin],
          jwks_uri: mcp_jwks_uri(ctx, config),
          scopes_supported: config[:scopes],
          bearer_methods_supported: ["header"],
          resource_signing_alg_values_supported: mcp_signing_algs(ctx, config)
        }
      end

      def mcp_jwks_uri(ctx, config)
        config.dig(:oidc_config, :metadata, :jwks_uri) ||
          config.dig(:advertised_metadata, :jwks_uri) ||
          "#{OAuthProtocol.endpoint_base(ctx)}/oauth2/jwks"
      end

      def mcp_signing_algs(ctx, config)
        jwt_plugin = ctx.context.options.plugins.find { |plugin| plugin.id == "jwt" }
        alg = config.dig(:jwt, :jwks, :key_pair_config, :alg) ||
          jwt_plugin&.options&.dig(:jwks, :key_pair_config, :alg)
        [alg || "EdDSA"]
      end

      def jwks(ctx, config)
        jwt_config = config[:jwt] || {}
        BetterAuth::Plugins.create_jwk(ctx, jwt_config) if BetterAuth::Plugins.all_jwks(ctx, jwt_config).empty?
        {keys: BetterAuth::Plugins.public_jwks(ctx, jwt_config).map { |key| BetterAuth::Plugins.public_jwk(key, jwt_config) }}
      end
    end
  end
end
