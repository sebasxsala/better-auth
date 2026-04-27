# frozen_string_literal: true

require "bcrypt"
require "test_helper"

class BetterAuthPasswordTest < Minitest::Test
  def test_hash_and_verify_password_with_default_scrypt
    digest = BetterAuth::Password.hash("correct horse battery staple")

    refute_equal "correct horse battery staple", digest
    assert_match(/\A[0-9a-f]{32}:[0-9a-f]{128}\z/, digest)
    assert BetterAuth::Password.verify(password: "correct horse battery staple", hash: digest)
    refute BetterAuth::Password.verify(password: "wrong", hash: digest)
  end

  def test_verify_rejects_invalid_hashes
    refute BetterAuth::Password.verify(password: "password", hash: "not-a-password-hash")
  end

  def test_hash_and_verify_password_with_bcrypt
    digest = BetterAuth::Password.hash("correct horse battery staple", hasher: :bcrypt)

    assert_match(/\Abcrypt_sha256\$/, digest)
    assert BetterAuth::Password.verify(password: "correct horse battery staple", hash: digest)
    refute BetterAuth::Password.verify(password: "wrong", hash: digest)
  end

  def test_verify_supports_legacy_raw_bcrypt_hashes
    legacy = BCrypt::Password.create("legacy-password")

    assert BetterAuth::Password.verify(password: "legacy-password", hash: legacy.to_s)
    refute BetterAuth::Password.verify(password: "wrong", hash: legacy.to_s)
  end

  def test_bcrypt_hasher_requires_optional_bcrypt_gem
    BetterAuth::Password.stub(:bcrypt_password_class, nil) do
      error = assert_raises(BetterAuth::Error) do
        BetterAuth::Password.hash("password", hasher: :bcrypt)
      end

      assert_includes error.message, "Add `gem \"bcrypt\"`"
    end
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
    password = "parole\u0301123!"
    digest = BetterAuth::Password.hash(password)

    assert BetterAuth::Password.verify(password: "parol\u00e9123!", hash: digest)
  end

  def test_custom_hash_and_verify_callbacks_support_upstream_shape
    hasher = ->(password) { "custom:#{password.reverse}" }
    verifier = ->(data) { data[:hash] == "custom:#{data[:password].reverse}" }
    digest = BetterAuth::Password.hash("secret", hasher: hasher)

    assert_equal "custom:terces", digest
    assert BetterAuth::Password.verify(password: "secret", hash: digest, verifier: verifier)
    refute BetterAuth::Password.verify(password: "wrong", hash: digest, verifier: verifier)
  end

  def test_custom_verify_callbacks_support_existing_ruby_shape
    verifier = ->(password, digest) { digest == "legacy:#{password}" }

    assert BetterAuth::Password.verify(password: "secret", hash: "legacy:secret", verifier: verifier)
  end
end
