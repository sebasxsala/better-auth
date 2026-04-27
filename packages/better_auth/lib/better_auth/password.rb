# frozen_string_literal: true

require "bcrypt"
require "digest"

module BetterAuth
  module Password
    PREFIX = "bcrypt_sha256$"

    module_function

    def hash(password, hasher: nil)
      return hasher.call(password) if hasher.respond_to?(:call)

      "#{PREFIX}#{BCrypt::Password.create(password_input(password))}"
    end

    def verify(password:, hash:, verifier: nil)
      return verifier.call(password, hash) if verifier.respond_to?(:call)

      digest = hash.to_s
      if digest.start_with?(PREFIX)
        BCrypt::Password.new(digest.delete_prefix(PREFIX)) == password_input(password)
      else
        BCrypt::Password.new(digest) == password.to_s
      end
    rescue BCrypt::Errors::InvalidHash
      false
    end

    def password_input(password)
      Digest::SHA256.hexdigest(password.to_s)
    end
  end
end
