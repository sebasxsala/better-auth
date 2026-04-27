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

  def test_hashes_use_unique_salts
    password = "samePassword123!"

    refute_equal BetterAuth::Password.hash(password), BetterAuth::Password.hash(password)
  end

  def test_password_verification_is_case_sensitive
    password = "CaseSensitivePassword123!"
    digest = BetterAuth::Password.hash(password)

    refute BetterAuth::Password.verify(password: password.downcase, hash: digest)
    refute BetterAuth::Password.verify(password: password.upcase, hash: digest)
  end

  def test_long_passwords_are_not_truncated_by_bcrypt
    password = "#{"a" * 100}correct"
    digest = BetterAuth::Password.hash(password)

    assert BetterAuth::Password.verify(password: password, hash: digest)
    refute BetterAuth::Password.verify(password: "#{"a" * 100}wrong", hash: digest)
  end

  def test_password_hashing_handles_unicode
    password = "пароль123!"
    digest = BetterAuth::Password.hash(password)

    assert BetterAuth::Password.verify(password: password, hash: digest)
  end
end
