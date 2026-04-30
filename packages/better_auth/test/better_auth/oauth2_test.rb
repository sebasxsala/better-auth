# frozen_string_literal: true

require "test_helper"

class BetterAuthOAuth2Test < Minitest::Test
  def test_validate_token_verifies_rs256_token_with_matching_kid_audience_and_issuer
    rsa = OpenSSL::PKey::RSA.generate(2048)
    jwk = JWT::JWK.new(rsa.public_key, kid: "rsa-key").export
    token = JWT.encode({"sub" => "user", "aud" => "api", "iss" => "issuer"}, rsa, "RS256", {"kid" => "rsa-key"})

    payload = BetterAuth::OAuth2.validate_token(token, jwks: {"keys" => [jwk]}, audience: "api", issuer: "issuer")

    assert_equal "user", payload["sub"]
  end

  def test_validate_token_allows_signature_verification_without_claim_filters
    rsa = OpenSSL::PKey::RSA.generate(2048)
    jwk = JWT::JWK.new(rsa.public_key, kid: "rsa-key").export
    token = JWT.encode({"sub" => "user", "aud" => "api", "iss" => "issuer"}, rsa, "RS256", {"kid" => "rsa-key"})

    payload = BetterAuth::OAuth2.validate_token(token, jwks: {"keys" => [jwk]})

    assert_equal "user", payload["sub"]
  end

  def test_validate_token_verifies_es256_token_and_rejects_wrong_kid_audience_or_issuer
    ec = OpenSSL::PKey::EC.generate("prime256v1")
    jwk = JWT::JWK.new(ec, kid: "ec-key").export
    token = JWT.encode({"sub" => "user", "aud" => "api", "iss" => "issuer"}, ec, "ES256", {"kid" => "ec-key"})

    assert_equal "user", BetterAuth::OAuth2.validate_token(token, jwks: {"keys" => [jwk]}, audience: "api", issuer: "issuer")["sub"]
    assert_raises(BetterAuth::APIError) { BetterAuth::OAuth2.validate_token(token, jwks: {"keys" => []}, audience: "api", issuer: "issuer") }
    assert_raises(BetterAuth::APIError) { BetterAuth::OAuth2.validate_token(token, jwks: {"keys" => [jwk.merge("kid" => "other")]}, audience: "api", issuer: "issuer") }
    assert_raises(BetterAuth::APIError) { BetterAuth::OAuth2.validate_token(token, jwks: {"keys" => [jwk]}, audience: "other", issuer: "issuer") }
    assert_raises(BetterAuth::APIError) { BetterAuth::OAuth2.validate_token(token, jwks: {"keys" => [jwk]}, audience: "api", issuer: "other") }
  end

  def test_refresh_access_token_maps_expiration_fields
    response = {
      "access_token" => "access",
      "refresh_token" => "refresh",
      "expires_in" => 60,
      "refresh_token_expires_in" => 120,
      "token_type" => "Bearer",
      "scope" => "read write",
      "id_token" => "id"
    }
    fetcher = ->(_url, _request) { response }

    tokens = BetterAuth::OAuth2.refresh_access_token(
      refresh_token: "old",
      token_endpoint: "https://provider.example/token",
      options: {client_id: "client", client_secret: "secret"},
      fetcher: fetcher
    )

    assert_equal "access", tokens[:access_token]
    assert_equal "refresh", tokens[:refresh_token]
    assert_equal "Bearer", tokens[:token_type]
    assert_equal ["read", "write"], tokens[:scopes]
    assert_instance_of Time, tokens[:access_token_expires_at]
    assert_instance_of Time, tokens[:refresh_token_expires_at]
  end

  def test_refresh_access_token_omits_refresh_expiration_when_provider_omits_it
    fetcher = ->(_url, _request) { {"access_token" => "access", "expires_in" => 60} }

    tokens = BetterAuth::OAuth2.refresh_access_token(
      refresh_token: "old",
      token_endpoint: "https://provider.example/token",
      options: {client_id: "client"},
      fetcher: fetcher
    )

    assert tokens[:access_token_expires_at]
    refute tokens.key?(:refresh_token_expires_at)
  end
end
