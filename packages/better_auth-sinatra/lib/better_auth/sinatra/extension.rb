# frozen_string_literal: true

module BetterAuth
  module Sinatra
    module Extension
      def self.registered(app)
        app.extend ClassMethods
        app.helpers Helpers
      end

      module ClassMethods
        def better_auth(at: BetterAuth::Configuration::DEFAULT_BASE_PATH, auth: nil, **overrides)
          mount_path = normalize_better_auth_mount_path(at)
          config = BetterAuth::Sinatra.configuration.copy
          yield config if block_given?
          config.base_path = mount_path
          options = config.to_auth_options.merge(overrides)
          auth_instance = auth || BetterAuth.auth(options)

          set :better_auth_auth, auth_instance
          set :better_auth_mount_path, mount_path
          use BetterAuth::Sinatra::MountedApp, -> { settings.better_auth_auth }, mount_path: mount_path
        end

        private

        def normalize_better_auth_mount_path(path)
          normalized = path.to_s
          normalized = "/#{normalized}" unless normalized.start_with?("/")
          normalized = normalized.squeeze("/")
          (normalized == "/") ? normalized : normalized.delete_suffix("/")
        end
      end
    end
  end
end
