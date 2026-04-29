# frozen_string_literal: true

module BetterAuth
  module Hanami
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

        return path_info if path_info == @mount_path || path_info.start_with?("#{@mount_path}/")

        normalize_path("#{@mount_path}/#{path_info.delete_prefix("/")}")
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
