# frozen_string_literal: true

require "test_helper"

class BetterAuthCryptoTest < Minitest::Test
  def test_random_string_uses_url_safe_alphabet
    value = BetterAuth::Crypto.random_string(64)

    assert_equal 64, value.length
    assert_match(/\A[A-Za-z0-9\-_]+\z/, value)
  end

  def test_hmac_signatures_verify_in_constant_time
    signature = BetterAuth::Crypto.hmac_signature("session-token", "secret")

    assert BetterAuth::Crypto.verify_hmac_signature("session-token", signature, "secret")
    refute BetterAuth::Crypto.verify_hmac_signature("tampered", signature, "secret")
  end

  def test_symmetric_encryption_round_trips_authenticated_payloads
    encrypted = BetterAuth::Crypto.symmetric_encrypt(key: "secret", data: "payload")

    refute_equal "payload", encrypted
    assert_equal "payload", BetterAuth::Crypto.symmetric_decrypt(key: "secret", data: encrypted)
    assert_nil BetterAuth::Crypto.symmetric_decrypt(key: "wrong", data: encrypted)
  end

  def test_jwt_helpers_sign_verify_and_reject_tampering
    token = BetterAuth::Crypto.sign_jwt({"sub" => "user-1"}, "secret", expires_in: 60)

    assert_equal "user-1", BetterAuth::Crypto.verify_jwt(token, "secret")["sub"]
    assert_nil BetterAuth::Crypto.verify_jwt("#{token}x", "secret")
  end
end
