# frozen_string_literal: true

require "digest"
require "openssl"
require "securerandom"
require_relative "error"

module BetterAuth
  module Password
    PREFIX = "bcrypt_sha256$"
    BCRYPT_PREFIXES = ["$2a$", "$2b$", "$2x$", "$2y$"].freeze
    SCRYPT = {
      N: 16_384,
      r: 16,
      p: 1,
      length: 64
    }.freeze

    module_function

    def hash(password, hasher: nil, algorithm: :scrypt)
      return hasher.call(password) if hasher.respond_to?(:call)

      case (hasher || algorithm || :scrypt).to_sym
      when :scrypt
        hash_scrypt(password)
      when :bcrypt
        hash_bcrypt(password)
      else
        raise Error, "Unsupported password hasher: #{hasher || algorithm}. Supported hashers are :scrypt and :bcrypt."
      end
    end

    def verify(password:, hash:, verifier: nil, algorithm: :scrypt)
      return call_verifier(verifier, password, hash) if verifier.respond_to?(:call)

      digest = hash.to_s
      if digest.start_with?(PREFIX)
        return verify_bcrypt(password_input(password), digest.delete_prefix(PREFIX))
      end

      return verify_bcrypt(password.to_s, digest) if bcrypt_hash?(digest)
      return verify_scrypt(password, digest) if scrypt_hash?(digest)

      false
    end

    def password_input(password)
      Digest::SHA256.hexdigest(password.to_s)
    end

    def hash_scrypt(password)
      salt = SecureRandom.random_bytes(16).unpack1("H*")
      key = scrypt_key(password, salt)
      "#{salt}:#{key.unpack1("H*")}"
    end

    def verify_scrypt(password, digest)
      salt, key = digest.to_s.split(":", 2)
      return false unless salt && key

      expected = scrypt_key(password, salt).unpack1("H*")
      return false unless expected.bytesize == key.bytesize

      OpenSSL.fixed_length_secure_compare(expected, key.downcase)
    rescue OpenSSL::KDF::KDFError, ArgumentError
      false
    end

    def scrypt_key(password, salt)
      OpenSSL::KDF.scrypt(
        password.to_s.unicode_normalize(:nfkc),
        salt: salt,
        N: SCRYPT.fetch(:N),
        r: SCRYPT.fetch(:r),
        p: SCRYPT.fetch(:p),
        length: SCRYPT.fetch(:length)
      )
    end

    def hash_bcrypt(password)
      klass = require_bcrypt!
      "#{PREFIX}#{klass.create(password_input(password))}"
    end

    def verify_bcrypt(password, digest)
      klass = require_bcrypt!
      klass.new(digest) == password.to_s
    rescue BCrypt::Errors::InvalidHash
      false
    end

    def bcrypt_hash?(digest)
      BCRYPT_PREFIXES.any? { |prefix| digest.start_with?(prefix) }
    end

    def scrypt_hash?(digest)
      /\A[0-9a-fA-F]{32}:[0-9a-fA-F]{128}\z/.match?(digest.to_s)
    end

    def call_verifier(verifier, password, digest)
      if verifier.arity == 1
        verifier.call(password: password, hash: digest)
      else
        verifier.call(password, digest)
      end
    end

    def bcrypt_password_class
      require "bcrypt"
      BCrypt::Password
    rescue LoadError
      nil
    end

    def require_bcrypt!
      bcrypt_password_class || raise(Error, "The :bcrypt password hasher requires the optional bcrypt gem. Add `gem \"bcrypt\"` to your Gemfile.")
    end
  end
end
