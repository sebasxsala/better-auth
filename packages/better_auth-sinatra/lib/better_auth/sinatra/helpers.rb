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
        result = auth.api.get_session(
          headers: better_auth_request_headers,
          return_headers: true
        )
        apply_better_auth_response_headers(result[:headers] || result["headers"] || {})
        result[:response] || result["response"]
      end

      def better_auth_request_headers
        request.env.each_with_object({}) do |(key, value), headers|
          case key
          when "CONTENT_TYPE"
            headers["content-type"] = value if value
          when "CONTENT_LENGTH"
            headers["content-length"] = value if value
          else
            next unless key.start_with?("HTTP_")

            headers[key.delete_prefix("HTTP_").downcase.tr("_", "-")] = value
          end
        end
      end

      def apply_better_auth_response_headers(headers)
        set_cookie = headers["set-cookie"] || headers["Set-Cookie"] || headers[:set_cookie]
        return if set_cookie.to_s.empty?

        existing = response.headers["set-cookie"].to_s
        response.headers["set-cookie"] = [existing, set_cookie.to_s].reject(&:empty?).join("\n")
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
