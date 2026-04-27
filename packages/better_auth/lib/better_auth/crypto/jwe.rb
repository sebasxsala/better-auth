# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "securerandom"

previous_verbose = $VERBOSE
$VERBOSE = nil
require "jwe"
$VERBOSE = previous_verbose

module BetterAuth
  module Crypto
    module JWE
      ALG = "dir"
      ENC = "A256CBC-HS512"
      INFO = "BetterAuth.js Generated Encryption Key"
      CLOCK_TOLERANCE = 15

      module_function

      def encode(payload, secret, salt, expires_in: 3600)
        claims = Crypto.stringify_keys(payload).merge(
          "iat" => Time.now.to_i,
          "exp" => Time.now.to_i + expires_in.to_i,
          "jti" => SecureRandom.uuid
        )
        key = encryption_key(secret, salt)
        ::JWE.encrypt(JSON.generate(claims), key, alg: ALG, enc: ENC, kid: thumbprint(key))
      end

      def decode(token, secret, salt)
        return nil if token.to_s.empty?

        header = protected_header(token)
        return nil unless valid_header?(header)
        return nil unless header["kid"].nil? || header["kid"] == thumbprint(encryption_key(secret, salt))

        payload = JSON.parse(::JWE.decrypt(token.to_s, encryption_key(secret, salt)))
        return nil if expired?(payload)

        payload
      rescue JSON::ParserError, ArgumentError, ::JWE::DecodeError, ::JWE::InvalidData, ::JWE::BadCEK
        nil
      end

      def encryption_key(secret, salt)
        OpenSSL::KDF.hkdf(secret.to_s, salt: salt.to_s, info: INFO, length: 64, hash: "SHA256")
      end

      def thumbprint(key)
        jwk = {
          "k" => Base64.urlsafe_encode64(key, padding: false),
          "kty" => "oct"
        }
        Crypto.base64url_encode(OpenSSL::Digest.digest("SHA256", JSON.generate(jwk)))
      end

      def protected_header(token)
        first_segment = token.to_s.split(".", 2).first
        JSON.parse(Crypto.base64url_decode(first_segment))
      rescue JSON::ParserError, ArgumentError
        {}
      end

      def valid_header?(header)
        header["alg"] == ALG && header["enc"] == ENC
      end

      def expired?(payload)
        payload["exp"] && payload["exp"].to_i < Time.now.to_i - CLOCK_TOLERANCE
      end
    end
  end
end
