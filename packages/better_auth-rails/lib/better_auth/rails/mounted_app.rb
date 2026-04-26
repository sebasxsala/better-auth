# frozen_string_literal: true

module BetterAuth
  module Rails
    class MountedApp
      def initialize(auth, mount_path:)
        @auth = auth
        @mount_path = normalize_path(mount_path)
      end

      def call(env)
        @auth.call(env.merge("PATH_INFO" => mounted_path_info(env)))
      end

      private

      def mounted_path_info(env)
        path_info = normalize_path(env["PATH_INFO"])
        script_name = normalize_path(env["SCRIPT_NAME"])
        prefix = (script_name == "/") ? @mount_path : script_name

        return path_info if path_info == prefix || path_info.start_with?("#{prefix}/")

        normalize_path("#{prefix}/#{path_info.delete_prefix("/")}")
      end

      def normalize_path(path)
        normalized = path.to_s
        normalized = "/#{normalized}" unless normalized.start_with?("/")
        normalized = normalized.squeeze("/")
        normalized = normalized.delete_suffix("/") unless normalized == "/"
        normalized.empty? ? "/" : normalized
      end
    end
  end
end
