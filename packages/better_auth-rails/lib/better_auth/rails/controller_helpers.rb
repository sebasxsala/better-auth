# frozen_string_literal: true

module BetterAuth
  module Rails
    module ControllerHelpers
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

      private

      def better_auth_session_data
        request.env["better_auth.session"] ||= resolve_better_auth_session
      end

      def resolve_better_auth_session
        context = BetterAuth::Endpoint::Context.new(
          path: request.path,
          method: request.request_method,
          query: request.query_parameters,
          body: {},
          params: {},
          headers: {"cookie" => request.get_header("HTTP_COOKIE")},
          context: BetterAuth::Rails.auth.context,
          request: request
        )
        BetterAuth::Session.find_current(context, disable_refresh: true)
      end
    end
  end
end
