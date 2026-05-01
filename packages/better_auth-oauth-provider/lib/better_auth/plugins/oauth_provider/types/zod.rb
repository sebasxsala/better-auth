# frozen_string_literal: true

module BetterAuth
  module Plugins
    module OAuthProvider
      module Types
        module Zod
          DANGEROUS_SCHEMES = ["javascript", "data", "vbscript"].freeze

          module_function

          def safe_url!(value, field: "url")
            OAuthProtocol.validate_safe_url!(value, field: field)
          end

          def safe_url?(value)
            safe_url!(value)
            true
          rescue APIError
            false
          end

          def authorization_query!(query)
            data = OAuthProtocol.stringify_keys(query || {})
            required = %w[client_id redirect_uri]
            missing = required.find { |key| data[key].to_s.empty? }
            raise APIError.new("BAD_REQUEST", message: "#{missing} is required") if missing
            raise APIError.new("BAD_REQUEST", message: "response_type must be code") if data["response_type"] && data["response_type"] != "code"
            raise APIError.new("BAD_REQUEST", message: "code_challenge_method must be S256") if data["code_challenge_method"] && data["code_challenge_method"] != "S256"

            safe_url!(data["redirect_uri"], field: "redirect_uri")
            data
          end

          def verification_value!(value)
            data = OAuthProtocol.stringify_keys(value || {})
            raise APIError.new("BAD_REQUEST", message: "type must be authorization_code") unless data["type"] == "authorization_code"
            raise APIError.new("BAD_REQUEST", message: "query is required") unless data["query"].is_a?(Hash)
            raise APIError.new("BAD_REQUEST", message: "sessionId is required") if data["sessionId"].to_s.empty?
            raise APIError.new("BAD_REQUEST", message: "userId is required") if data["userId"].to_s.empty?

            data
          end
        end
      end
    end
  end
end
