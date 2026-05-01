# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      DEFAULT_SCOPES = %w[openid profile email offline_access].freeze
      DEFAULT_GRANT_TYPES = [OAuthProtocol::AUTH_CODE_GRANT, OAuthProtocol::REFRESH_GRANT, OAuthProtocol::CLIENT_CREDENTIALS_GRANT].freeze

      module_function

      def normalize_config(options)
        incoming = BetterAuth::Plugins.normalize_hash(options || {})
        oidc = BetterAuth::Plugins.normalize_hash(incoming[:oidc_config] || {})
        base = {
          login_page: "/login",
          consent_page: "/oauth2/consent",
          resource: nil,
          scopes: DEFAULT_SCOPES,
          grant_types: DEFAULT_GRANT_TYPES,
          allow_dynamic_client_registration: true,
          allow_unauthenticated_client_registration: true,
          require_pkce: true,
          code_expires_in: 600,
          access_token_expires_in: 3600,
          refresh_token_expires_in: 604_800,
          m2m_access_token_expires_in: 3600,
          store_client_secret: "plain",
          prefix: {},
          store: OAuthProtocol.stores
        }
        config = base.merge(oidc.except(:metadata)).merge(incoming)
        config[:oidc_config] = oidc
        config[:scopes] = (Array(base[:scopes]) + Array(oidc[:scopes]) + Array(incoming[:scopes])).compact.map(&:to_s).uniq
        config[:grant_types] = Array(config[:grant_types]).map(&:to_s)
        config[:prefix] = BetterAuth::Plugins.normalize_hash(config[:prefix] || {})
        config
      end

      def set_cors_headers(ctx)
        ctx.set_header("Access-Control-Allow-Origin", "*")
        ctx.set_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        ctx.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        ctx.set_header("Access-Control-Max-Age", "86400")
      end

      def no_store_headers
        {"Cache-Control" => "no-store", "Pragma" => "no-cache"}
      end
    end
  end
end
