# frozen_string_literal: true

module BetterAuth
  module Hanami
    module ActionHelpers
      def current_session(request)
        data = better_auth_session_data(request)
        data&.fetch(:session, nil) || data&.fetch("session", nil)
      end

      def current_user(request)
        data = better_auth_session_data(request)
        data&.fetch(:user, nil) || data&.fetch("user", nil)
      end

      def authenticated?(request)
        !current_user(request).nil?
      end

      def require_authentication(request, response)
        return true if authenticated?(request)

        response.status = 401 if response.respond_to?(:status=)
        false
      end

      private

      def better_auth_session_data(request)
        env = request_env(request)
        return env["better_auth.session"] if env.key?("better_auth.session")

        env["better_auth.session"] = resolve_better_auth_session(request)
      end

      def resolve_better_auth_session(request)
        context = BetterAuth::Endpoint::Context.new(
          path: request_path(request),
          method: request_method(request),
          query: request_params(request),
          body: {},
          params: {},
          headers: {"cookie" => request_cookie(request)},
          context: BetterAuth::Hanami.auth.context,
          request: request
        )
        BetterAuth::Session.find_current(context, disable_refresh: true)
      end

      def request_env(request)
        request.respond_to?(:env) ? request.env : {}
      end

      def request_path(request)
        request.respond_to?(:path) ? request.path : "/"
      end

      def request_method(request)
        request.respond_to?(:request_method) ? request.request_method : "GET"
      end

      def request_params(request)
        request.respond_to?(:params) ? request.params : {}
      end

      def request_cookie(request)
        return request.get_header("HTTP_COOKIE") if request.respond_to?(:get_header)

        headers = request.respond_to?(:headers) ? request.headers : {}
        headers["cookie"] || headers["Cookie"]
      end
    end
  end
end
