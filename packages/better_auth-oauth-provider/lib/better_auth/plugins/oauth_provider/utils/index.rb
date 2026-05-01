# frozen_string_literal: true

require "base64"
require "json"

module BetterAuth
  module Plugins
    module OAuthProvider
      module Utils
        module_function

        def get_oauth_provider_plugin(ctx)
          ctx.get_plugin("oauth-provider")
        end

        def get_jwt_plugin(ctx)
          plugin = ctx.get_plugin("jwt")
          raise Error, "jwt_config" unless plugin

          plugin
        end

        def normalize_timestamp_value(value)
          return nil if value.nil?

          seconds = OAuthProtocol.timestamp_seconds(value)
          seconds ? Time.at(seconds) : nil
        end

        def resolve_session_auth_time(value)
          normalize_timestamp_value(OAuthProtocol.session_auth_time(value))
        end

        def verify_oauth_query_params(oauth_query, secret)
          pairs = URI.decode_www_form(oauth_query.to_s)
          signature = pairs.reverse_each.find { |key, _value| key == "sig" }&.last
          unsigned_pairs = pairs.filter_map { |key, value| [key, value] unless key == "sig" }
          exp = unsigned_pairs.reverse_each.find { |key, _value| key == "exp" }&.last.to_i
          unsigned = URI.encode_www_form(unsigned_pairs)

          !!signature &&
            exp >= Time.now.to_i &&
            Crypto.verify_hmac_signature(unsigned, signature, secret, encoding: :base64url)
        rescue ArgumentError
          false
        end

        def parse_client_metadata(metadata)
          return nil if metadata.nil? || metadata == ""
          return OAuthProtocol.stringify_keys(metadata) if metadata.is_a?(Hash)

          OAuthProtocol.stringify_keys(JSON.parse(metadata.to_s))
        end

        def parse_prompt(prompt)
          OAuthProtocol.parse_scopes(prompt).select do |value|
            Types::OAuth::PROMPTS.include?(value)
          end.uniq
        end

        def basic_to_client_credentials(authorization)
          return nil unless authorization.to_s.start_with?("Basic ")

          decoded = Base64.decode64(authorization.to_s.delete_prefix("Basic "))
          id, secret = decoded.split(":", 2)
          if id.to_s.empty? || secret.to_s.empty?
            raise APIError.new(
              "BAD_REQUEST",
              message: "invalid authorization header format",
              body: {error: "invalid_client", error_description: "invalid authorization header format"}
            )
          end

          {client_id: id, client_secret: secret}
        rescue ArgumentError
          raise APIError.new(
            "BAD_REQUEST",
            message: "invalid authorization header format",
            body: {error: "invalid_client", error_description: "invalid authorization header format"}
          )
        end

        def store_token(token, storage_method: "hashed")
          case storage_method
          when "hashed", :hashed
            Crypto.sha256(token.to_s, encoding: :base64url)
          else
            if storage_method.is_a?(Hash) && storage_method[:hash].respond_to?(:call)
              storage_method[:hash].call(token.to_s)
            else
              raise Error, "storeToken: unsupported storageMethod type '#{storage_method}'"
            end
          end
        end

        alias_method :get_stored_token, :store_token

        def store_client_secret(ctx, client_secret, storage_method: "hashed")
          OAuthProtocol.store_client_secret_value(ctx, client_secret, storage_method)
        end
      end
    end
  end
end
