# frozen_string_literal: true

module BetterAuth
  module Plugins
    module OAuthProvider
      module Client
        ID = "oauth-provider-client"

        module_function

        def parse_signed_query(search)
          query = search.to_s.sub(/\A\?/, "")
          return nil if query.empty?

          pairs = URI.decode_www_form(query)
          return nil unless pairs.any? { |key, _value| key == "sig" }

          signed_pairs = []
          pairs.each do |key, value|
            signed_pairs << [key, value]
            break if key == "sig"
          end
          URI.encode_www_form(signed_pairs)
        end
      end
    end
  end
end
