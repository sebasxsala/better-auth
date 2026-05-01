# frozen_string_literal: true

module BetterAuth
  module APIKey
    module PluginFactory
      module_function

      def build(configurations = {}, options = nil)
        config = BetterAuth::APIKey::Configuration.normalize(configurations, options)
        BetterAuth::Plugin.new(
          id: "api-key",
          version: BetterAuth::APIKey::VERSION,
          hooks: {
            before: [
              {
                matcher: ->(ctx) { !!BetterAuth::APIKey::Session.header_config(ctx, config) },
                handler: ->(ctx) { BetterAuth::APIKey::Session.hook(ctx, config) }
              }
            ]
          },
          endpoints: {
            create_api_key: BetterAuth::APIKey::Routes::CreateAPIKey.endpoint(config),
            verify_api_key: BetterAuth::APIKey::Routes::VerifyAPIKey.endpoint(config),
            get_api_key: BetterAuth::APIKey::Routes::GetAPIKey.endpoint(config),
            update_api_key: BetterAuth::APIKey::Routes::UpdateAPIKey.endpoint(config),
            delete_api_key: BetterAuth::APIKey::Routes::DeleteAPIKey.endpoint(config),
            list_api_keys: BetterAuth::APIKey::Routes::ListAPIKeys.endpoint(config),
            delete_all_expired_api_keys: BetterAuth::APIKey::Routes::DeleteAllExpiredAPIKeys.endpoint(config)
          },
          schema: BetterAuth::APIKey::SchemaDefinition.schema(config, config[:schema]),
          error_codes: BetterAuth::APIKey::ERROR_CODES,
          options: config
        )
      end
    end
  end
end
