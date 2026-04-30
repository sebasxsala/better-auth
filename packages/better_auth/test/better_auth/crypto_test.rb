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

  def test_secret_rotation_envelope_parser_matches_upstream_shape
    assert_nil BetterAuth::Crypto.parse_envelope("abcdef1234567890")
    assert_nil BetterAuth::Crypto.parse_envelope("$ba$abc$abcdef")
    assert_equal({version: 2, ciphertext: "abcdef1234567890"}, BetterAuth::Crypto.parse_envelope("$ba$2$abcdef1234567890"))
  end

  def test_symmetric_encryption_uses_versioned_envelopes_and_decrypts_old_versions
    old_config = BetterAuth::SecretConfig.new(
      keys: {1 => "old-secret-that-is-long-enough-for-validation"},
      current_version: 1
    )
    encrypted = BetterAuth::Crypto.symmetric_encrypt(key: old_config, data: "old payload")

    assert_match(/\A\$ba\$1\$/, encrypted)

    new_config = BetterAuth::SecretConfig.new(
      keys: {
        2 => "new-secret-that-is-long-enough-for-validation",
        1 => "old-secret-that-is-long-enough-for-validation"
      },
      current_version: 2
    )

    assert_equal "old payload", BetterAuth::Crypto.symmetric_decrypt(key: new_config, data: encrypted)
  end

  def test_symmetric_encryption_decrypts_legacy_payload_with_legacy_secret
    legacy = BetterAuth::Crypto.symmetric_encrypt(key: "legacy-secret-that-is-long-enough", data: "legacy payload")
    config = BetterAuth::SecretConfig.new(
      keys: {2 => "new-secret-that-is-long-enough-for-validation"},
      current_version: 2,
      legacy_secret: "legacy-secret-that-is-long-enough"
    )

    assert_equal "legacy payload", BetterAuth::Crypto.symmetric_decrypt(key: config, data: legacy)
    assert_nil BetterAuth::Crypto.symmetric_decrypt(
      key: BetterAuth::SecretConfig.new(keys: {2 => "new-secret-that-is-long-enough-for-validation"}, current_version: 2),
      data: legacy
    )
  end

  def test_jwt_helpers_sign_verify_and_reject_tampering
    token = BetterAuth::Crypto.sign_jwt({"sub" => "user-1"}, "secret", expires_in: 60)

    assert_equal "user-1", BetterAuth::Crypto.verify_jwt(token, "secret")["sub"]
    assert_nil BetterAuth::Crypto.verify_jwt("#{token}x", "secret")
  end

  def test_symmetric_jwe_uses_compact_jwe_header_and_round_trips
    token = BetterAuth::Crypto.symmetric_encode_jwt(
      {"sub" => "user-1"},
      "secret-with-enough-entropy-for-jwe",
      "better-auth-session",
      expires_in: 60
    )

    segments = token.split(".")
    assert_equal 5, segments.length

    header = JSON.parse(BetterAuth::Crypto.base64url_decode(segments.first))
    assert_equal "dir", header.fetch("alg")
    assert_equal "A256CBC-HS512", header.fetch("enc")
    assert header.fetch("kid").is_a?(String)
    refute_includes token, "user-1"

    payload = BetterAuth::Crypto.symmetric_decode_jwt(
      token,
      "secret-with-enough-entropy-for-jwe",
      "better-auth-session"
    )

    assert_equal "user-1", payload.fetch("sub")
    assert payload.fetch("iat").is_a?(Integer)
    assert payload.fetch("exp").is_a?(Integer)
    assert payload.fetch("jti").is_a?(String)
  end

  def test_symmetric_jwe_rejects_wrong_secret_wrong_salt_and_tampering
    token = BetterAuth::Crypto.symmetric_encode_jwt(
      {"sub" => "user-1"},
      "secret-with-enough-entropy-for-jwe",
      "better-auth-session",
      expires_in: 60
    )

    assert_nil BetterAuth::Crypto.symmetric_decode_jwt(token, "wrong-secret", "better-auth-session")
    assert_nil BetterAuth::Crypto.symmetric_decode_jwt(token, "secret-with-enough-entropy-for-jwe", "wrong-salt")
    assert_nil BetterAuth::Crypto.symmetric_decode_jwt("#{token}x", "secret-with-enough-entropy-for-jwe", "better-auth-session")
  end

  def test_symmetric_jwe_decodes_rotated_and_legacy_tokens
    old_config = BetterAuth::SecretConfig.new(
      keys: {1 => "old-secret-that-is-long-enough-for-jwe"},
      current_version: 1
    )
    token = BetterAuth::Crypto.symmetric_encode_jwt({"sub" => "user-1"}, old_config, "better-auth-session", expires_in: 60)

    new_config = BetterAuth::SecretConfig.new(
      keys: {
        2 => "new-secret-that-is-long-enough-for-jwe",
        1 => "old-secret-that-is-long-enough-for-jwe"
      },
      current_version: 2
    )

    assert_equal "user-1", BetterAuth::Crypto.symmetric_decode_jwt(token, new_config, "better-auth-session").fetch("sub")

    legacy_token = BetterAuth::Crypto.symmetric_encode_jwt(
      {"sub" => "legacy-user"},
      "legacy-secret-that-is-long-enough-for-jwe",
      "better-auth-session",
      expires_in: 60
    )
    legacy_config = BetterAuth::SecretConfig.new(
      keys: {2 => "new-secret-that-is-long-enough-for-jwe"},
      current_version: 2,
      legacy_secret: "legacy-secret-that-is-long-enough-for-jwe"
    )

    assert_equal "legacy-user", BetterAuth::Crypto.symmetric_decode_jwt(legacy_token, legacy_config, "better-auth-session").fetch("sub")
    assert_nil BetterAuth::Crypto.symmetric_decode_jwt(token, legacy_config, "better-auth-session")
  end
end
