# frozen_string_literal: true

module BetterAuth
  module Sinatra
    module Helpers
      def current_session
        data = better_auth_session_data
        data&.fetch(:session, nil) || data&.fetch("session", nil)
      end

      def current_user
        data = better_auth_session_data
        data&.fetch(:user, nil) || data&.fetch("user", nil)
      end

      def authenticated?
        !current_user.nil?
      end

      def require_authentication
        return true if authenticated?

        halt 401, ""
      end

      private

      def better_auth_session_data
        return request.env["better_auth.session"] if request.env.key?("better_auth.session")

        request.env["better_auth.session"] = resolve_better_auth_session
      end

      def resolve_better_auth_session
        auth = better_auth_auth
        auth.context.prepare_for_request!(request) if auth.context.respond_to?(:prepare_for_request!)
        context = BetterAuth::Endpoint::Context.new(
          path: request.path_info,
          method: request.request_method,
          query: request.GET,
          body: {},
          params: params,
          headers: {"cookie" => request.env["HTTP_COOKIE"]},
          context: auth.context,
          request: request
        )
        BetterAuth::Session.find_current(context, disable_refresh: true)
      end

      def better_auth_auth
        if respond_to?(:settings) && settings.respond_to?(:better_auth_auth)
          settings.better_auth_auth
        else
          BetterAuth::Sinatra.auth
        end
      end
    end
  end
end
