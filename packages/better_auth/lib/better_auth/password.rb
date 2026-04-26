# frozen_string_literal: true

require "bcrypt"

module BetterAuth
  module Password
    module_function

    def hash(password, hasher: nil)
      return hasher.call(password) if hasher.respond_to?(:call)

      BCrypt::Password.create(password.to_s)
    end

    def verify(password:, hash:, verifier: nil)
      return verifier.call(password, hash) if verifier.respond_to?(:call)

      BCrypt::Password.new(hash.to_s) == password.to_s
    rescue BCrypt::Errors::InvalidHash
      false
    end
  end
end
