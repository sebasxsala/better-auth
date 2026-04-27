# frozen_string_literal: true

require "base64"
require "json"
require "jwt"
require "openssl"
require "securerandom"
require_relative "crypto/jwe"

module BetterAuth
  module Crypto
    URL_SAFE_ALPHABET = [*"a".."z", *"A".."Z", *"0".."9", "-", "_"].freeze

    module_function

    def random_string(length = 32)
      Array.new(length) { URL_SAFE_ALPHABET[SecureRandom.random_number(URL_SAFE_ALPHABET.length)] }.join
    end

    def uuid
      SecureRandom.uuid
    end

    def sha256(value, encoding: :hex)
      digest = OpenSSL::Digest.digest("SHA256", value.to_s)
      (encoding == :base64url) ? base64url_encode(digest) : digest.unpack1("H*")
    end

    def hmac_signature(value, secret, encoding: :base64)
      digest = OpenSSL::HMAC.digest("SHA256", secret.to_s, value.to_s)
      (encoding == :base64url) ? base64url_encode(digest) : Base64.strict_encode64(digest)
    end

    def verify_hmac_signature(value, signature, secret, encoding: :base64)
      expected = hmac_signature(value, secret, encoding: encoding)
      constant_time_compare(expected, signature.to_s)
    end

    def constant_time_compare(left, right)
      return false unless left.bytesize == right.bytesize

      OpenSSL.fixed_length_secure_compare(left, right)
    end

    def symmetric_encrypt(key:, data:)
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      cipher.key = OpenSSL::Digest.digest("SHA256", key.to_s)
      iv = SecureRandom.random_bytes(12)
      cipher.iv = iv
      ciphertext = cipher.update(data.to_s) + cipher.final
      payload = {
        "iv" => base64url_encode(iv),
        "data" => base64url_encode(ciphertext),
        "tag" => base64url_encode(cipher.auth_tag)
      }
      base64url_encode(JSON.generate(payload))
    end

    def symmetric_decrypt(key:, data:)
      payload = JSON.parse(base64url_decode(data.to_s))
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.decrypt
      cipher.key = OpenSSL::Digest.digest("SHA256", key.to_s)
      cipher.iv = base64url_decode(payload.fetch("iv"))
      cipher.auth_tag = base64url_decode(payload.fetch("tag"))
      cipher.update(base64url_decode(payload.fetch("data"))) + cipher.final
    rescue JSON::ParserError, KeyError, OpenSSL::Cipher::CipherError, ArgumentError
      nil
    end

    def sign_jwt(payload, secret, expires_in: 3600)
      claims = stringify_keys(payload).merge(
        "iat" => Time.now.to_i,
        "exp" => Time.now.to_i + expires_in.to_i
      )
      JWT.encode(claims, secret.to_s, "HS256")
    end

    def verify_jwt(token, secret)
      decoded, = JWT.decode(token.to_s, secret.to_s, true, algorithm: "HS256")
      decoded
    rescue JWT::DecodeError
      nil
    end

    def symmetric_encode_jwt(payload, secret, salt, expires_in: 3600)
      JWE.encode(payload, secret, salt, expires_in: expires_in)
    end

    def symmetric_decode_jwt(token, secret, salt)
      JWE.decode(token, secret, salt)
    end

    def base64url_encode(value)
      Base64.urlsafe_encode64(value.to_s, padding: false)
    end

    def base64url_decode(value)
      Base64.urlsafe_decode64(value.to_s)
    end

    def stringify_keys(value)
      return value.each_with_object({}) { |(key, object_value), result| result[key.to_s] = stringify_keys(object_value) } if value.is_a?(Hash)
      return value.map { |entry| stringify_keys(entry) } if value.is_a?(Array)

      value
    end
  end
end
