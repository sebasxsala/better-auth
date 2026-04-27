# frozen_string_literal: true

module BetterAuth
  module Sinatra
    class MountedApp
      def initialize(app, auth, mount_path:)
        @app = app
        @auth = auth
        @mount_path = normalize_path(mount_path)
      end

      def call(env)
        return auth.call(env) if mounted_path?(env["PATH_INFO"])

        @app.call(env)
      end

      private

      def auth
        return @auth.call if @auth.respond_to?(:call) && !@auth.respond_to?(:context)

        @auth
      end

      def mounted_path?(path)
        normalized = normalize_path(path)
        return true if @mount_path == "/"

        normalized == @mount_path || normalized.start_with?("#{@mount_path}/")
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
