# frozen_string_literal: true

require "json"

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

        if prefers_json_response?
          error = BetterAuth::APIError.new("UNAUTHORIZED")
          halt 401, {"content-type" => "application/json"}, JSON.generate(error.to_h)
        end

        halt 401, ""
      end

      private

      def prefers_json_response?
        accept = request.env["HTTP_ACCEPT"].to_s
        return false if accept.empty? || accept == "*/*"

        preferred = request.preferred_type(["application/json", "text/html"]) if request.respond_to?(:preferred_type)
        return preferred.to_s == "application/json" if preferred

        accept.split(",").any? do |entry|
          media_type = entry.split(";", 2).first.to_s.strip
          media_type == "application/json" || media_type.end_with?("+json")
        end
      end

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
