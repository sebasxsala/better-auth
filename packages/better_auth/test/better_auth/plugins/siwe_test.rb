# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsSiweTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"
  WALLET = "0x000000000000000000000000000000000000dEaD"

  def test_nonce_is_stored_per_wallet_and_chain
    auth = build_auth

    result = auth.api.get_siwe_nonce(body: {walletAddress: WALLET, chainId: 137})

    assert_equal "nonce-1", result[:nonce]
    stored = auth.context.internal_adapter.find_verification_value("siwe:#{WALLET.downcase}:137")
    refute_nil stored
    assert_equal "nonce-1", stored["value"]
  end

  def test_verify_creates_wallet_user_account_session_and_consumes_nonce
    auth = build_auth(ens_lookup: ->(wallet_address:) { {name: "vitalik.eth", avatar: "https://example.com/v.png"} })
    auth.api.get_siwe_nonce(body: {walletAddress: WALLET, chainId: 1})

    status, headers, body = auth.api.verify_siwe_message(
      body: {message: "valid-message", signature: "valid-signature", walletAddress: WALLET, chainId: 1},
      as_response: true
    )
    data = JSON.parse(body.first)

    assert_equal 200, status
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_equal true, data.fetch("success")
    assert_equal WALLET.downcase, data.dig("user", "walletAddress")
    assert_equal 1, data.dig("user", "chainId")

    wallet = auth.context.adapter.find_one(model: "walletAddress", where: [{field: "address", value: WALLET.downcase}])
    refute_nil wallet
    assert_equal true, wallet["isPrimary"]
    user = auth.context.internal_adapter.find_user_by_id(wallet["userId"])
    assert_equal "vitalik.eth", user["name"]
    assert_equal "https://example.com/v.png", user["image"]
    assert auth.context.internal_adapter.find_account_by_provider_id("#{WALLET.downcase}:1", "siwe")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.verify_siwe_message(body: {message: "valid-message", signature: "valid-signature", walletAddress: WALLET, chainId: 1})
    end
    assert_equal 401, error.status_code
    assert_equal "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE", error.status
  end

  def test_verify_rejects_missing_nonce_invalid_signature_and_invalid_wallet
    auth = build_auth

    missing_nonce = assert_raises(BetterAuth::APIError) do
      auth.api.verify_siwe_message(body: {message: "valid-message", signature: "valid-signature", walletAddress: WALLET})
    end
    assert_equal 401, missing_nonce.status_code

    auth.api.get_siwe_nonce(body: {walletAddress: WALLET})
    invalid_signature = assert_raises(BetterAuth::APIError) do
      auth.api.verify_siwe_message(body: {message: "valid-message", signature: "bad-signature", walletAddress: WALLET})
    end
    assert_equal 401, invalid_signature.status_code
    assert_equal "Unauthorized: Invalid SIWE signature", invalid_signature.message

    invalid_wallet = assert_raises(BetterAuth::APIError) do
      auth.api.get_siwe_nonce(body: {walletAddress: "invalid"})
    end
    assert_equal 400, invalid_wallet.status_code
  end

  def test_anonymous_false_requires_valid_email
    auth = build_auth(anonymous: false)

    auth.api.get_siwe_nonce(body: {walletAddress: WALLET})
    missing_email = assert_raises(BetterAuth::APIError) do
      auth.api.verify_siwe_message(body: {message: "valid-message", signature: "valid-signature", walletAddress: WALLET})
    end
    assert_equal 400, missing_email.status_code
    assert_equal "Email is required when anonymous is disabled.", missing_email.message

    invalid_email = assert_raises(BetterAuth::APIError) do
      auth.api.verify_siwe_message(body: {message: "valid-message", signature: "valid-signature", walletAddress: WALLET, email: "not-an-email"})
    end
    assert_equal 400, invalid_email.status_code

    auth.api.get_siwe_nonce(body: {walletAddress: WALLET})
    result = auth.api.verify_siwe_message(body: {message: "valid-message", signature: "valid-signature", walletAddress: WALLET, email: "wallet@example.com"})
    assert_equal true, result[:success]
    wallet = auth.context.adapter.find_one(model: "walletAddress", where: [{field: "address", value: WALLET.downcase}])
    user = auth.context.internal_adapter.find_user_by_id(wallet["userId"])
    assert_equal "wallet@example.com", user["email"]
  end

  def test_same_wallet_on_different_chains_reuses_user_and_adds_address
    auth = build_auth

    auth.api.get_siwe_nonce(body: {walletAddress: WALLET, chainId: 1})
    first = auth.api.verify_siwe_message(body: {message: "valid-message", signature: "valid-signature", walletAddress: WALLET, chainId: 1})
    auth.api.get_siwe_nonce(body: {walletAddress: WALLET, chainId: 137})
    second = auth.api.verify_siwe_message(body: {message: "valid-message", signature: "valid-signature", walletAddress: WALLET, chainId: 137})

    assert_equal first[:user][:id], second[:user][:id]
    wallets = auth.context.adapter.find_many(model: "walletAddress", where: [{field: "address", value: WALLET.downcase}])
    assert_equal 2, wallets.length
    assert_equal [1, 137], wallets.map { |wallet| wallet["chainId"] }.sort
    refute wallets.find { |wallet| wallet["chainId"] == 137 }["isPrimary"]
  end

  private

  def build_auth(options = {})
    nonce = 0
    verify_message = options.delete(:verify_message) || lambda do |message:, signature:, address:, chain_id:, cacao:|
      signature == "valid-signature" &&
        message == "valid-message" &&
        address == WALLET.downcase &&
        chain_id.to_i.positive? &&
        cacao[:p][:nonce].start_with?("nonce-")
    end

    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.siwe({
          domain: "example.com",
          get_nonce: -> {
            nonce += 1
            "nonce-#{nonce}"
          },
          verify_message: verify_message
        }.merge(options))
      ]
    )
  end
end
