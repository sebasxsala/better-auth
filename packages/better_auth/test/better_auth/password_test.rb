# frozen_string_literal: true

require "test_helper"

class BetterAuthPasswordTest < Minitest::Test
  def test_hash_and_verify_password_with_bcrypt
    digest = BetterAuth::Password.hash("correct horse battery staple")

    refute_equal "correct horse battery staple", digest
    assert BetterAuth::Password.verify(password: "correct horse battery staple", hash: digest)
    refute BetterAuth::Password.verify(password: "wrong", hash: digest)
  end

  def test_verify_rejects_invalid_hashes
    refute BetterAuth::Password.verify(password: "password", hash: "not-a-bcrypt-hash")
  end
end
