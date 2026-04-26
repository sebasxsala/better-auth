# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPluginsAPIKeyTest < Minitest::Test
  SECRET = "phase-nine-api-key-secret-with-enough-entropy"

  def test_create_verify_get_list_update_and_delete_api_key
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "api-key@example.com")

    created = auth.api.create_api_key(
      headers: {"cookie" => cookie},
      body: {name: "primary", prefix: "ba_", metadata: {plan: "pro"}, permissions: {repo: ["read"]}}
    )

    assert_match(/\Aba_[A-Za-z]+\z/, created[:key])
    assert_equal "ba_", created[:prefix]
    assert_equal "primary", created[:name]
    assert_equal({"plan" => "pro"}, created[:metadata])

    verified = auth.api.verify_api_key(body: {key: created[:key], permissions: {repo: ["read"]}})
    assert_equal true, verified[:valid]
    assert_equal created[:id], verified[:key][:id]
    refute verified[:key].key?("key")

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    assert_equal "primary", fetched[:name]

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})
    assert_equal [created[:id]], listed.map { |entry| entry[:id] || entry["id"] }

    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], name: "renamed", enabled: false})
    assert_equal "renamed", updated[:name]
    assert_equal false, updated[:enabled]

    disabled = assert_raises(BetterAuth::APIError) { auth.api.verify_api_key(body: {key: created[:key]}) }
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_DISABLED"], disabled.message

    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id]}))
    assert_raises(BetterAuth::APIError) { auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]}) }
  end

  def test_expiration_remaining_refill_and_rate_limit
    auth = build_auth(rate_limit: {enabled: true, time_window: 60_000, max_requests: 1})
    cookie = sign_up_cookie(auth, email: "limits@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    expired = auth.api.create_api_key(body: {userId: user_id, expiresIn: -1})
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_EXPIRED"], assert_raises(BetterAuth::APIError) {
      auth.api.verify_api_key(body: {key: expired[:key]})
    }.message

    limited = auth.api.create_api_key(body: {userId: user_id, remaining: 1})
    assert_equal true, auth.api.verify_api_key(body: {key: limited[:key]})[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["USAGE_EXCEEDED"], assert_raises(BetterAuth::APIError) {
      auth.api.verify_api_key(body: {key: limited[:key]})
    }.message

    rate_limited = auth.api.create_api_key(body: {userId: user_id, rateLimitEnabled: true, rateLimitMax: 1, rateLimitTimeWindow: 60_000})
    assert_equal true, auth.api.verify_api_key(body: {key: rate_limited[:key]})[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["RATE_LIMIT_EXCEEDED"], assert_raises(BetterAuth::APIError) {
      auth.api.verify_api_key(body: {key: rate_limited[:key]})
    }.message

    refill = auth.api.create_api_key(body: {userId: user_id, remaining: 0, refillAmount: 2, refillInterval: 1})
    stored = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: refill[:id]}])
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: stored["id"]}], update: {lastRequest: Time.now - 10, lastRefillAt: Time.now - 10})
    assert_equal true, auth.api.verify_api_key(body: {key: refill[:key]})[:valid]
  end

  def test_secondary_storage_and_api_key_session
    storage = MemoryStorage.new
    auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      fallback_to_database: true,
      enable_session_for_api_keys: true
    )
    cookie = sign_up_cookie(auth, email: "storage-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "storage"})

    assert storage.keys.any? { |key| key.include?(created[:id]) }
    session = auth.api.get_session(headers: {"x-api-key" => created[:key]})

    assert_equal "storage-key@example.com", session[:user]["email"]
    assert_equal created[:id], session[:session]["id"]
  end

  def test_validation_errors_match_upstream
    auth = build_auth(require_name: true)
    cookie = sign_up_cookie(auth, email: "validation-key@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["NAME_REQUIRED"], error.message

    client_server_only = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "bad", userId: "someone-else"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"], client_server_only.message
  end

  def build_auth(options = {})
    BetterAuth.auth({
      secret: SECRET,
      email_and_password: {enabled: true},
      secondary_storage: options.delete(:secondary_storage),
      plugins: [BetterAuth::Plugins.api_key(options)]
    }.compact)
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "API Key"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  class MemoryStorage
    attr_reader :values

    def initialize
      @values = {}
    end

    def get(key)
      values[key]
    end

    def set(key, value, _ttl = nil)
      values[key] = value
    end

    def delete(key)
      values.delete(key)
    end

    def keys
      values.keys
    end
  end
end
