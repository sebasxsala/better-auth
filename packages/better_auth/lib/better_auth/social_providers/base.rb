# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "openssl"
require "uri"

module BetterAuth
  module SocialProviders
    module Base
      module_function

      def authorization_url(endpoint, params)
        uri = URI(endpoint)
        query = URI.decode_www_form(uri.query.to_s)
        params.compact.each do |key, value|
          next if value == ""

          query << [key.to_s, Array(value).join(" ")]
        end
        uri.query = URI.encode_www_form(query)
        uri.to_s
      end

      def pkce_challenge(verifier)
        digest = OpenSSL::Digest.digest("SHA256", verifier.to_s)
        Base64.urlsafe_encode64(digest, padding: false)
      end

      def post_form(url, form)
        uri = URI(url)
        response = Net::HTTP.post_form(uri, form.transform_keys(&:to_s))
        JSON.parse(response.body)
      end

      def get_json(url, headers = {})
        uri = URI(url)
        request = Net::HTTP::Get.new(uri)
        headers.each { |key, value| request[key.to_s] = value.to_s }
        response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |http| http.request(request) }
        JSON.parse(response.body)
      end

      def access_token(tokens)
        tokens[:access_token] || tokens["access_token"] || tokens[:accessToken] || tokens["accessToken"]
      end

      def id_token(tokens)
        tokens[:id_token] || tokens["id_token"] || tokens[:idToken] || tokens["idToken"]
      end

      def decode_jwt_payload(token)
        _header, payload, _signature = token.to_s.split(".", 3)
        return {} unless payload

        JSON.parse(Base64.urlsafe_decode64(padded_base64(payload)))
      rescue JSON::ParserError, ArgumentError
        {}
      end

      def padded_base64(value)
        value + ("=" * ((4 - value.length % 4) % 4))
      end
    end
  end
end
