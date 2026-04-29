# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthPluginsAPIKeyTest < Minitest::Test
  SECRET = "phase-nine-api-key-secret-with-enough-entropy"

  def test_public_hasher_and_schema_match_upstream_package_contract
    plugin = BetterAuth::Plugins.api_key

    assert_equal BetterAuth::Crypto.sha256("api-key-value", encoding: :base64url), BetterAuth::Plugins.default_api_key_hasher("api-key-value")
    refute plugin.schema.fetch(:apikey).fetch(:fields).key?(:userId)
  end

  def test_create_verify_get_list_update_and_delete_api_key
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "api-key@example.com")

    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(
      body: {userId: user_id, name: "primary", prefix: "ba_", metadata: {plan: "pro"}, permissions: {repo: ["read"]}}
    )

    assert_match(/\Aba_[A-Za-z]+\z/, created[:key])
    assert_equal "ba_", created[:prefix]
    assert_equal "primary", created[:name]
    assert_equal({"plan" => "pro"}, created[:metadata])

    verified = auth.api.verify_api_key(body: {key: created[:key], permissions: {repo: ["read"]}})
    assert_equal true, verified[:valid]
    assert_equal created[:id], verified[:key][:id]
    assert_nil verified[:error]
    refute verified[:key].key?("key")

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    assert_equal "primary", fetched[:name]

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})
    assert_equal [created[:id]], listed.fetch(:apiKeys).map { |entry| entry[:id] || entry["id"] }
    assert_equal 1, listed.fetch(:total)

    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], name: "renamed", enabled: false})
    assert_equal "renamed", updated[:name]
    assert_equal false, updated[:enabled]

    disabled = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal false, disabled[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_DISABLED"], disabled[:error][:message]
    assert_nil disabled[:key]

    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id]}))
    assert_raises(BetterAuth::APIError) { auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]}) }
  end

  def test_expiration_remaining_refill_and_rate_limit
    auth = build_auth(rate_limit: {enabled: true, time_window: 60_000, max_requests: 1})
    cookie = sign_up_cookie(auth, email: "limits@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_SMALL"], assert_raises(BetterAuth::APIError) {
      auth.api.create_api_key(body: {userId: user_id, expiresIn: 60 * 60 * 12})
    }.message

    expired = auth.api.create_api_key(body: {userId: user_id})
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: expired[:id]}], update: {expiresAt: Time.now - 10})
    expired_result = auth.api.verify_api_key(body: {key: expired[:key]})
    assert_equal false, expired_result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_EXPIRED"], expired_result[:error][:message]

    limited = auth.api.create_api_key(body: {userId: user_id, remaining: 1})
    assert_equal true, auth.api.verify_api_key(body: {key: limited[:key]})[:valid]
    usage_exceeded = auth.api.verify_api_key(body: {key: limited[:key]})
    assert_equal false, usage_exceeded[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["USAGE_EXCEEDED"], usage_exceeded[:error][:message]

    rate_limited = auth.api.create_api_key(body: {userId: user_id, rateLimitEnabled: true, rateLimitMax: 1, rateLimitTimeWindow: 60_000})
    assert_equal true, auth.api.verify_api_key(body: {key: rate_limited[:key]})[:valid]
    rate_error = auth.api.verify_api_key(body: {key: rate_limited[:key]})
    assert_equal false, rate_error[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["RATE_LIMIT_EXCEEDED"], rate_error[:error][:message]

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
      enable_session_for_api_keys: true,
      session: {store_session_in_database: true}
    )
    cookie = sign_up_cookie(auth, email: "storage-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "storage"})

    assert storage.keys.any? { |key| key.include?(created[:id]) }
    session = auth.api.get_session(headers: {"x-api-key" => created[:key]})

    assert_equal "storage-key@example.com", session[:user]["email"]
    assert_equal created[:id], session[:session]["id"]
  end

  def test_api_key_session_respects_disabled_ip_tracking
    storage = MemoryStorage.new
    auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      fallback_to_database: true,
      enable_session_for_api_keys: true,
      session: {store_session_in_database: true},
      advanced: {ip_address: {disable_ip_tracking: true}}
    )
    cookie = sign_up_cookie(auth, email: "ip-disabled-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "storage"})

    session = auth.api.get_session(headers: {"x-api-key" => created[:key], "x-forwarded-for" => "203.0.113.10"})

    assert_nil session[:session]["ipAddress"]
  end

  def test_api_key_session_is_not_created_when_disabled
    auth = build_auth(default_key_length: 12, enable_session_for_api_keys: false)
    cookie = sign_up_cookie(auth, email: "session-disabled-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    assert_nil auth.api.get_session(headers: {"x-api-key" => created[:key]})
  end

  def test_api_key_session_validation_statuses_match_upstream
    auth = build_auth(default_key_length: 12, enable_session_for_api_keys: true, rate_limit: {enabled: false})
    cookie = sign_up_cookie(auth, email: "session-status-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    disabled = auth.api.create_api_key(body: {userId: user_id})
    auth.api.update_api_key(body: {userId: user_id, keyId: disabled[:id], enabled: false})
    disabled_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_session(headers: {"x-api-key" => disabled[:key]})
    end
    assert_equal "UNAUTHORIZED", disabled_error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_DISABLED"], disabled_error.message

    expired = auth.api.create_api_key(body: {userId: user_id})
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: expired[:id]}], update: {expiresAt: Time.now - 10})
    expired_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_session(headers: {"x-api-key" => expired[:key]})
    end
    assert_equal "UNAUTHORIZED", expired_error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_EXPIRED"], expired_error.message

    limited = auth.api.create_api_key(body: {userId: user_id, remaining: 1})
    assert auth.api.get_session(headers: {"x-api-key" => limited[:key]})
    usage_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_session(headers: {"x-api-key" => limited[:key]})
    end
    assert_equal "TOO_MANY_REQUESTS", usage_error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["USAGE_EXCEEDED"], usage_error.message
  end

  def test_secondary_storage_fallback_invalidates_and_rebuilds_reference_list
    storage = MemoryStorage.new
    auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      fallback_to_database: true,
      default_key_length: 12
    )
    cookie = sign_up_cookie(auth, email: "fallback-ref-list-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    created = auth.api.create_api_key(body: {userId: user_id})

    assert_nil storage.get("api-key:by-ref:#{user_id}")

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})

    assert_equal [created[:id]], listed.fetch(:apiKeys).map { |entry| entry[:id] }
    assert_equal [created[:id]], JSON.parse(storage.get("api-key:by-ref:#{user_id}"))
  end

  def test_secondary_storage_fallback_get_warms_cache_from_database
    storage = MemoryStorage.new
    auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      fallback_to_database: true,
      default_key_length: 12
    )
    cookie = sign_up_cookie(auth, email: "fallback-get-warm-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "warm"})

    storage.clear
    assert_nil storage.get("api-key:by-id:#{created[:id]}")

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})

    assert_equal created[:id], fetched[:id]
    assert storage.get("api-key:by-id:#{created[:id]}")
    assert storage.get("api-key:#{auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])["key"]}")
  end

  def test_secondary_storage_pure_mode_crud_ttl_metadata_limits_and_custom_storage
    storage = MemoryStorage.new
    auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      enable_metadata: true,
      default_key_length: 12
    )
    cookie = sign_up_cookie(auth, email: "pure-storage-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    created = auth.api.create_api_key(
      body: {
        userId: user_id,
        name: "pure",
        expiresIn: 60 * 60 * 24 + 1,
        metadata: {plan: "premium"},
        rateLimitEnabled: true,
        rateLimitMax: 2,
        rateLimitTimeWindow: 60_000
      }
    )

    assert storage.get("api-key:by-id:#{created[:id]}")
    assert_equal [created[:id]], JSON.parse(storage.get("api-key:by-ref:#{user_id}"))
    assert storage.ttls.fetch("api-key:by-id:#{created[:id]}").positive?

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})
    first_verify = auth.api.verify_api_key(body: {key: created[:key]})
    second_verify = auth.api.verify_api_key(body: {key: created[:key]})
    rate_limited = auth.api.verify_api_key(body: {key: created[:key]})
    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], name: "updated-pure"})
    deleted = auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id]})

    assert_equal({"plan" => "premium"}, fetched[:metadata])
    assert_includes listed[:apiKeys].map { |entry| entry[:id] }, created[:id]
    assert_equal true, first_verify[:valid]
    assert_equal true, second_verify[:valid]
    assert_equal false, rate_limited[:valid]
    assert_equal "RATE_LIMITED", rate_limited[:error][:code]
    assert_equal "updated-pure", updated[:name]
    assert_equal({success: true}, deleted)
    assert_nil storage.get("api-key:by-id:#{created[:id]}")

    quota_key = auth.api.create_api_key(body: {userId: user_id, remaining: 2, rateLimitEnabled: false})
    quota_result = auth.api.verify_api_key(body: {key: quota_key[:key]})
    assert_equal true, quota_result[:valid]
    assert_equal 1, quota_result[:key][:remaining]

    global_storage = MemoryStorage.new
    custom_storage = MemoryStorage.new
    custom_auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: global_storage,
      custom_storage: custom_storage,
      default_key_length: 12
    )
    custom_cookie = sign_up_cookie(custom_auth, email: "custom-storage-key@example.com")
    custom_key = custom_auth.api.create_api_key(headers: {"cookie" => custom_cookie}, body: {})

    assert custom_storage.get("api-key:by-id:#{custom_key[:id]}")
    assert_nil global_storage.get("api-key:by-id:#{custom_key[:id]}")
    custom_auth.api.get_api_key(headers: {"cookie" => custom_cookie}, query: {id: custom_key[:id]})
    custom_auth.api.delete_api_key(headers: {"cookie" => custom_cookie}, body: {keyId: custom_key[:id]})
    assert custom_storage.get_calls.any? { |key| key == "api-key:by-id:#{custom_key[:id]}" }
    assert custom_storage.delete_calls.any? { |key| key == "api-key:by-id:#{custom_key[:id]}" }
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
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"], client_server_only.message
  end

  def test_create_rejects_server_only_properties_from_authenticated_client
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "client-server-only-key@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {permissions: {repo: ["read"]}})
    end

    assert_equal "BAD_REQUEST", error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"], error.message
  end

  def test_create_allows_nil_metadata_and_remaining_from_authenticated_client
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "client-nil-fields-key@example.com")

    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {metadata: nil, remaining: nil})

    assert_nil created[:metadata]
    assert_nil created[:remaining]
  end

  def test_create_respects_nil_expiration_and_refill_without_remaining
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "create-nil-expiration-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    no_expiration = auth.api.create_api_key(body: {userId: user_id, expiresIn: nil})
    refill = auth.api.create_api_key(body: {userId: user_id, refillAmount: 10, refillInterval: 1000})

    assert_nil no_expiration[:expiresAt]
    assert_nil refill[:remaining]
    assert_equal 10, refill[:refillAmount]
    assert_equal 1000, refill[:refillInterval]
  end

  def test_create_defaults_match_upstream_record_shape
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "create-defaults-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    created = auth.api.create_api_key(body: {userId: user_id})
    stored = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])

    assert_nil created[:lastRefillAt]
    assert_nil stored["lastRefillAt"]
    refute created.key?(:userId)
    refute stored.key?("userId")
    assert_match(/\A[A-Za-z]{12}\z/, created[:key])
  end

  def test_create_rate_limit_hashing_start_and_metadata_options_match_upstream
    rate_auth = build_auth(default_key_length: 12, rate_limit: {enabled: false, time_window: 1000, max_requests: 10})
    cookie = sign_up_cookie(rate_auth, email: "create-options-key@example.com")
    user_id = rate_auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    default_rate = rate_auth.api.create_api_key(body: {userId: user_id})
    disabled_rate = rate_auth.api.create_api_key(body: {userId: user_id, rateLimitEnabled: false})

    assert_equal false, default_rate[:rateLimitEnabled]
    assert_equal 1000, default_rate[:rateLimitTimeWindow]
    assert_equal 10, default_rate[:rateLimitMax]
    assert_equal false, disabled_rate[:rateLimitEnabled]

    raw_auth = build_auth(default_key_length: 12, disable_key_hashing: true)
    raw_cookie = sign_up_cookie(raw_auth, email: "raw-key@example.com")
    raw_key = raw_auth.api.create_api_key(headers: {"cookie" => raw_cookie}, body: {})
    raw_stored = raw_auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: raw_key[:id]}])
    assert_equal raw_key[:key], raw_stored["key"]
    assert_equal true, raw_auth.api.verify_api_key(body: {key: raw_key[:key]})[:valid]

    hidden_start_auth = build_auth(default_key_length: 12, starting_characters_config: {should_store: false})
    hidden_cookie = sign_up_cookie(hidden_start_auth, email: "hidden-start-key@example.com")
    assert_nil hidden_start_auth.api.create_api_key(headers: {"cookie" => hidden_cookie}, body: {})[:start]

    custom_start_auth = build_auth(default_key_length: 12, starting_characters_config: {should_store: true, characters_length: 3})
    custom_cookie = sign_up_cookie(custom_start_auth, email: "custom-start-key@example.com")
    custom_start = custom_start_auth.api.create_api_key(headers: {"cookie" => custom_cookie}, body: {})
    assert_equal custom_start[:key][0, 3], custom_start[:start]

    metadata_auth = build_auth(default_key_length: 12, enable_metadata: false)
    metadata_cookie = sign_up_cookie(metadata_auth, email: "metadata-disabled-create-key@example.com")
    metadata_error = assert_raises(BetterAuth::APIError) do
      metadata_auth.api.create_api_key(headers: {"cookie" => metadata_cookie}, body: {metadata: {test: "test-123"}})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["METADATA_DISABLED"], metadata_error.message
  end

  def test_create_rejects_upstream_server_only_fields_from_authenticated_client
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "client-server-only-fields-key@example.com")

    %i[refillAmount refillInterval rateLimitMax rateLimitTimeWindow].each do |field|
      error = assert_raises(BetterAuth::APIError) do
        auth.api.create_api_key(headers: {"cookie" => cookie}, body: {field => 10})
      end
      assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"], error.message
    end
  end

  def test_create_validates_name_prefix_expiration_refill_and_metadata_like_upstream
    auth = build_auth(default_key_length: 12, enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "create-validation-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    name_error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "test-api-key-that-is-longer-than-the-allowed-maximum"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_NAME_LENGTH"], name_error.message

    prefix_error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {prefix: "bad prefix"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_PREFIX_LENGTH"], prefix_error.message

    max_expiration_error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {userId: user_id, expiresIn: 60 * 60 * 24 * 365 * 10})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_LARGE"], max_expiration_error.message

    invalid_metadata = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {metadata: "invalid"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_METADATA_TYPE"], invalid_metadata.message

    interval_without_amount = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {userId: user_id, refillInterval: 1000})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["REFILL_AMOUNT_AND_INTERVAL_REQUIRED"], interval_without_amount.message

    amount_without_interval = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {userId: user_id, refillAmount: 10})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["REFILL_INTERVAL_AND_AMOUNT_REQUIRED"], amount_without_interval.message

    valid_metadata = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {metadata: {test: "test"}})
    assert_equal({"test" => "test"}, valid_metadata[:metadata])

    zero_remaining_refill = auth.api.create_api_key(body: {userId: user_id, remaining: 0, refillAmount: 10, refillInterval: 1000})
    assert_equal 0, zero_remaining_refill[:remaining]
    assert_equal 10, zero_remaining_refill[:refillAmount]
  end

  def test_multiple_configurations_default_prefix_and_config_filters
    auth = build_auth([
      {config_id: "public-api", default_prefix: "pub_", default_key_length: 12},
      {config_id: "internal-api", default_prefix: "int_", default_key_length: 12},
      {config_id: "default", default_prefix: "def_", default_key_length: 12}
    ])
    cookie = sign_up_cookie(auth, email: "multi-config-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    public_key = auth.api.create_api_key(body: {configId: "public-api", userId: user_id})
    internal_key = auth.api.create_api_key(body: {configId: "internal-api", userId: user_id})
    default_key = auth.api.create_api_key(body: {userId: user_id})

    assert_equal "public-api", public_key[:configId]
    assert_equal "pub_", public_key[:prefix]
    assert_match(/\Apub_[A-Za-z]+\z/, public_key[:key])
    assert_equal user_id, public_key[:referenceId]
    assert_equal "internal-api", internal_key[:configId]
    assert_equal "int_", internal_key[:prefix]
    assert_equal "default", default_key[:configId]
    assert_equal "def_", default_key[:prefix]

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {configId: "public-api"})
    assert_equal [public_key[:id]], listed.fetch(:apiKeys).map { |entry| entry[:id] }
    assert_equal 1, listed.fetch(:total)

    verified = auth.api.verify_api_key(body: {configId: "internal-api", key: internal_key[:key]})
    assert_equal true, verified[:valid]
    assert_equal "internal-api", verified[:key][:configId]
  end

  def test_multiple_configurations_resolve_correct_config_for_crud
    auth = build_auth([
      {config_id: "public-api", default_prefix: "pub_", default_key_length: 12, rate_limit: {enabled: true, max_requests: 100, time_window: 60_000}},
      {config_id: "internal-api", default_prefix: "int_", default_key_length: 12, rate_limit: {enabled: true, max_requests: 1000, time_window: 60_000}},
      {config_id: "default", default_prefix: "def_", default_key_length: 12}
    ])
    cookie = sign_up_cookie(auth, email: "multi-crud-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    public_key = auth.api.create_api_key(body: {configId: "public-api", userId: user_id, name: "public"})
    internal_key = auth.api.create_api_key(body: {configId: "internal-api", userId: user_id, name: "internal"})

    assert_equal 100, public_key[:rateLimitMax]
    assert_equal 1000, internal_key[:rateLimitMax]
    assert_equal 100, auth.api.verify_api_key(body: {key: public_key[:key], configId: "public-api"})[:key][:rateLimitMax]
    assert_equal "int_", auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: internal_key[:id], configId: "internal-api"})[:prefix]

    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: public_key[:id], configId: "public-api", name: "updated-public"})
    assert_equal "public-api", updated[:configId]
    assert_equal "updated-public", updated[:name]

    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: internal_key[:id], configId: "internal-api"}))
    assert_raises(BetterAuth::APIError) do
      auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: internal_key[:id], configId: "internal-api"})
    end
  end

  def test_multiple_configuration_validation
    assert_raises(BetterAuth::Error) do
      BetterAuth::Plugins.api_key([{config_id: "duplicate"}, {config_id: "duplicate"}])
    end

    assert_raises(BetterAuth::Error) do
      BetterAuth::Plugins.api_key([{config_id: "valid"}, {}])
    end
  end

  def test_list_paginates_sorts_and_returns_upstream_shape
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "list-shape-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.api.create_api_key(body: {userId: user_id, name: "zulu"})
    auth.api.create_api_key(body: {userId: user_id, name: "alpha"})
    auth.api.create_api_key(body: {userId: user_id, name: "mike"})

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {limit: 2, offset: 1, sortBy: "name", sortDirection: "asc"})

    assert_equal %w[mike zulu], listed.fetch(:apiKeys).map { |entry| entry[:name] }
    assert_equal 3, listed.fetch(:total)
    assert_equal 2, listed.fetch(:limit)
    assert_equal 1, listed.fetch(:offset)
  end

  def test_list_rejects_invalid_pagination_query
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "invalid-list-query-key@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {limit: -1})
    end

    assert_equal "BAD_REQUEST", error.status
  end

  def test_verify_invalid_key_returns_error_payload
    auth = build_auth(default_key_length: 12)

    result = auth.api.verify_api_key(body: {key: "missing-key"})

    assert_equal false, result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"], result[:error][:message]
    assert_equal "INVALID_API_KEY", result[:error][:code]
    assert_nil result[:key]
  end

  def test_verify_requires_key_in_body_and_does_not_fallback_to_headers
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "verify-header-fallback-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    result = auth.api.verify_api_key(headers: {"x-api-key" => created[:key]}, body: {})

    assert_equal false, result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"], result[:error][:message]
    assert_equal "INVALID_API_KEY", result[:error][:code]
    assert_nil result[:key]
  end

  def test_verify_runs_custom_validator_before_database_validation
    auth = build_auth(default_key_length: 12, custom_api_key_validator: ->(_options) { false })
    cookie = sign_up_cookie(auth, email: "validator-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal false, result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"], result[:error][:message]
    assert_equal "KEY_NOT_FOUND", result[:error][:code]
    assert_nil result[:key]
  end

  def test_verify_permission_failures_match_upstream_error_code
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "permission-failure-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, permissions: {repo: ["read"]}})

    result = auth.api.verify_api_key(body: {key: created[:key], permissions: {repo: ["write"]}})

    assert_equal false, result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_NOT_FOUND"], result[:error][:message]
    assert_equal "KEY_NOT_FOUND", result[:error][:code]
  end

  def test_verify_rate_limit_error_includes_upstream_code_and_retry_details
    auth = build_auth(default_key_length: 12, rate_limit: {enabled: true, time_window: 60_000, max_requests: 1})
    cookie = sign_up_cookie(auth, email: "rate-details-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    assert_equal true, auth.api.verify_api_key(body: {key: created[:key]})[:valid]
    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal false, result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["RATE_LIMIT_EXCEEDED"], result[:error][:message]
    assert_equal "RATE_LIMITED", result[:error][:code]
    assert result[:error][:details][:tryAgainIn].positive?
  end

  def test_verify_does_not_increment_request_count_when_rate_limit_is_disabled
    auth = build_auth(default_key_length: 12, rate_limit: {enabled: false, time_window: 60_000, max_requests: 1})
    cookie = sign_up_cookie(auth, email: "disabled-rate-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    assert_equal true, auth.api.verify_api_key(body: {key: created[:key]})[:valid]

    stored = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
    assert_equal 0, stored["requestCount"]
    assert stored["lastRequest"]
  end

  def test_verify_rate_limit_window_reset_and_permissions_metadata_shape
    auth = build_auth(default_key_length: 12, enable_metadata: true, rate_limit: {enabled: true, time_window: 60_000, max_requests: 1})
    cookie = sign_up_cookie(auth, email: "verify-shape-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, metadata: {scope: "read"}, permissions: {files: ["read", "write"]}})

    first = auth.api.verify_api_key(body: {key: created[:key], permissions: {files: ["read"]}})
    assert_equal true, first[:valid]
    assert_equal({"scope" => "read"}, first[:key][:metadata])
    assert_equal({"files" => ["read", "write"]}, first[:key][:permissions])

    limited = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal false, limited[:valid]
    assert_equal "RATE_LIMITED", limited[:error][:code]

    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {lastRequest: Time.now - 120, requestCount: 1})
    reset = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal true, reset[:valid]
    assert_equal 1, reset[:key][:requestCount]

    no_permissions = auth.api.create_api_key(body: {userId: user_id, permissions: nil})
    permission_result = auth.api.verify_api_key(body: {key: no_permissions[:key], permissions: {files: ["write"]}})
    assert_equal false, permission_result[:valid]
    assert_equal "KEY_NOT_FOUND", permission_result[:error][:code]
  end

  def test_verify_remaining_refill_cycles_match_upstream
    auth = build_auth(default_key_length: 12, rate_limit: {enabled: false})
    cookie = sign_up_cookie(auth, email: "refill-cycles-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 1, refillAmount: 3, refillInterval: 3_600_000})

    first = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal true, first[:valid]
    assert_equal 0, first[:key][:remaining]

    before_refill = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal false, before_refill[:valid]
    assert_equal "USAGE_EXCEEDED", before_refill[:error][:code]

    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {createdAt: Time.now - 3700, lastRefillAt: Time.now - 3700})
    refilled = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal true, refilled[:valid]
    assert_equal 2, refilled[:key][:remaining]

    2.times { assert_equal true, auth.api.verify_api_key(body: {key: created[:key]})[:valid] }
    exhausted = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal false, exhausted[:valid]
    assert_equal "USAGE_EXCEEDED", exhausted[:error][:code]

    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {lastRefillAt: Time.now - 3700})
    second_refill = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal true, second_refill[:valid]
    assert_equal 2, second_refill[:key][:remaining]
  end

  def test_default_permissions_callable_and_prefix_validation
    calls = []
    auth = build_auth(
      default_key_length: 12,
      permissions: {
        default_permissions: ->(reference_id, ctx) {
          calls << [reference_id, ctx.path]
          {repo: ["read"]}
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "permissions-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    invalid_prefix = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {userId: user_id, prefix: "bad prefix"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_PREFIX_LENGTH"], invalid_prefix.message

    created = auth.api.create_api_key(body: {userId: user_id})
    assert_equal({"repo" => ["read"]}, created[:permissions])
    assert_equal [[user_id, "/api-key/create"]], calls
    assert_equal true, auth.api.verify_api_key(body: {key: created[:key], permissions: {repo: ["read"]}})[:valid]
  end

  def test_organization_owned_api_keys_require_membership_permissions_and_filtering
    ac = BetterAuth::Plugins.create_access_control(
      organization: ["update", "delete"],
      member: ["create", "update", "delete"],
      invitation: ["create", "cancel"],
      team: ["create", "update", "delete"],
      ac: ["create", "read", "update", "delete"],
      apiKey: ["create", "read", "update", "delete"]
    )
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization(
          ac: ac,
          roles: {
            owner: ac.new_role(member: ["create", "update", "delete"], apiKey: ["create", "read", "update", "delete"]),
            member: ac.new_role(apiKey: ["read"])
          }
        ),
        BetterAuth::Plugins.api_key([
          {config_id: "user-keys", default_prefix: "usr_", references: "user", default_key_length: 12},
          {config_id: "org-keys", default_prefix: "org_", references: "organization", default_key_length: 12}
        ])
      ]
    )
    owner_cookie = sign_up_cookie(auth, email: "org-owner-key@example.com")
    member_cookie = sign_up_cookie(auth, email: "org-member-key@example.com")
    member_id = auth.api.get_session(headers: {"cookie" => member_cookie})[:user]["id"]
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "API Org", slug: "api-org"})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), userId: member_id, role: "member"})

    org_key = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id")})

    assert_equal "org-keys", org_key[:configId]
    assert_equal organization.fetch("id"), org_key[:referenceId]
    assert_equal "org_", org_key[:prefix]

    listed = auth.api.list_api_keys(headers: {"cookie" => member_cookie}, query: {organizationId: organization.fetch("id")})
    assert_equal [org_key[:id]], listed.fetch(:apiKeys).map { |entry| entry[:id] }

    insufficient = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => member_cookie}, body: {configId: "org-keys", keyId: org_key[:id], name: "blocked"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INSUFFICIENT_API_KEY_PERMISSIONS"], insufficient.message
  end

  def test_organization_owner_has_implicit_api_key_permissions
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.api_key([
          {config_id: "user-keys", references: "user", default_key_length: 12},
          {config_id: "org-keys", references: "organization", default_key_length: 12}
        ])
      ]
    )
    owner_cookie = sign_up_cookie(auth, email: "implicit-owner-key@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Implicit API Org", slug: "implicit-api-org"})

    org_key = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id")})
    updated = auth.api.update_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", keyId: org_key[:id], name: "owner-updated"})
    deleted = auth.api.delete_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", keyId: org_key[:id]})

    assert_equal organization.fetch("id"), org_key[:referenceId]
    assert_equal "owner-updated", updated[:name]
    assert_equal({success: true}, deleted)
  end

  def test_organization_api_key_denials_and_wrong_config_match_upstream
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.api_key([
          {config_id: "user-keys", references: "user", default_key_length: 12},
          {config_id: "org-keys", references: "organization", default_key_length: 12}
        ])
      ]
    )
    owner_cookie = sign_up_cookie(auth, email: "org-denial-owner-key@example.com")
    non_member_cookie = sign_up_cookie(auth, email: "org-denial-non-member-key@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Denied API Org", slug: "denied-api-org"})
    org_key = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id")})

    non_member = assert_raises(BetterAuth::APIError) do
      auth.api.list_api_keys(headers: {"cookie" => non_member_cookie}, query: {organizationId: organization.fetch("id")})
    end
    assert_equal "FORBIDDEN", non_member.status
    assert_equal "USER_NOT_MEMBER_OF_ORGANIZATION", non_member.code
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["USER_NOT_MEMBER_OF_ORGANIZATION"], non_member.message

    wrong_config = assert_raises(BetterAuth::APIError) do
      auth.api.get_api_key(headers: {"cookie" => owner_cookie}, query: {id: org_key[:id], configId: "user-keys"})
    end
    assert_equal "NOT_FOUND", wrong_config.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_NOT_FOUND"], wrong_config.message

    no_org_plugin = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.api_key([{config_id: "org-keys", references: "organization", default_key_length: 12}])]
    )
    cookie = sign_up_cookie(no_org_plugin, email: "missing-org-plugin-key@example.com")
    missing_plugin = assert_raises(BetterAuth::APIError) do
      no_org_plugin.api.create_api_key(headers: {"cookie" => cookie}, body: {configId: "org-keys", organizationId: "fake-org-id"})
    end
    assert_equal "INTERNAL_SERVER_ERROR", missing_plugin.status
    assert_equal "ORGANIZATION_PLUGIN_REQUIRED", missing_plugin.code
  end

  def test_organization_api_key_custom_roles_match_upstream
    ac = BetterAuth::Plugins.create_access_control(
      organization: ["update", "delete"],
      member: ["create", "update", "delete"],
      invitation: ["create", "cancel"],
      team: ["create", "update", "delete"],
      ac: ["create", "read", "update", "delete"],
      apiKey: ["create", "read", "update", "delete"]
    )
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization(
          ac: ac,
          roles: {
            owner: ac.new_role(member: ["create", "update", "delete"], apiKey: ["create", "read", "update", "delete"]),
            admin: ac.new_role(apiKey: ["create", "read", "update", "delete"]),
            member: ac.new_role(apiKey: ["read"]),
            restricted: ac.new_role({})
          }
        ),
        BetterAuth::Plugins.api_key([{config_id: "org-keys", references: "organization", default_key_length: 12}])
      ]
    )
    owner_cookie = sign_up_cookie(auth, email: "custom-role-owner-key@example.com")
    admin_cookie = sign_up_cookie(auth, email: "custom-role-admin-key@example.com")
    member_cookie = sign_up_cookie(auth, email: "custom-role-member-key@example.com")
    restricted_cookie = sign_up_cookie(auth, email: "custom-role-restricted-key@example.com")
    admin_id = auth.api.get_session(headers: {"cookie" => admin_cookie})[:user]["id"]
    member_id = auth.api.get_session(headers: {"cookie" => member_cookie})[:user]["id"]
    restricted_id = auth.api.get_session(headers: {"cookie" => restricted_cookie})[:user]["id"]
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Custom Role API Org", slug: "custom-role-api-org"})
    org_id = organization.fetch("id")
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org_id, userId: admin_id, role: "admin"})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org_id, userId: member_id, role: "member"})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org_id, userId: restricted_id, role: "restricted"})

    admin_key = auth.api.create_api_key(headers: {"cookie" => admin_cookie}, body: {configId: "org-keys", organizationId: org_id})
    assert_equal org_id, admin_key[:referenceId]
    assert_equal "admin-updated", auth.api.update_api_key(headers: {"cookie" => admin_cookie}, body: {configId: "org-keys", keyId: admin_key[:id], name: "admin-updated"})[:name]
    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => admin_cookie}, body: {configId: "org-keys", keyId: admin_key[:id]}))

    owner_key = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", organizationId: org_id})
    assert_includes auth.api.list_api_keys(headers: {"cookie" => member_cookie}, query: {organizationId: org_id})[:apiKeys].map { |entry| entry[:id] }, owner_key[:id]
    member_create = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => member_cookie}, body: {configId: "org-keys", organizationId: org_id})
    end
    assert_equal "INSUFFICIENT_API_KEY_PERMISSIONS", member_create.code

    restricted_list = assert_raises(BetterAuth::APIError) do
      auth.api.list_api_keys(headers: {"cookie" => restricted_cookie}, query: {organizationId: org_id})
    end
    assert_equal "INSUFFICIENT_API_KEY_PERMISSIONS", restricted_list.code
  end

  def test_update_auth_boundaries_match_upstream
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "owner-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, permissions: {repo: ["read"]}})

    unauthorized = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {keyId: created[:id], name: "stolen"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"], unauthorized.message

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {keyId: created[:id], userId: "different-user", name: "stolen"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_NOT_FOUND"], missing.message

    server_update = auth.api.update_api_key(body: {keyId: created[:id], userId: user_id, permissions: {repo: ["read", "write"]}})
    assert_equal({"repo" => ["read", "write"]}, server_update[:permissions])

    client_server_only = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], permissions: {repo: ["admin"]}})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"], client_server_only.message
  end

  def test_update_expires_in_nil_clears_existing_expiration
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "clear-expiration-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, expiresIn: 60 * 60 * 24 * 7})

    assert created[:expiresAt]

    updated = auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], expiresIn: nil})

    assert_nil updated[:expiresAt]
  end

  def test_update_validates_fields_and_supports_upstream_mutations
    auth = build_auth(default_key_length: 12, enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "update-validation-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    no_values = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id]})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["NO_VALUES_TO_UPDATE"], no_values.message

    name_too_short = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], name: ""})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_NAME_LENGTH"], name_too_short.message

    invalid_metadata = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], metadata: "invalid"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_METADATA_TYPE"], invalid_metadata.message

    missing_interval = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], refillAmount: 10})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["REFILL_INTERVAL_AND_AMOUNT_REQUIRED"], missing_interval.message

    updated = auth.api.update_api_key(
      body: {
        userId: user_id,
        keyId: created[:id],
        expiresIn: 60 * 60 * 24 * 7,
        remaining: 50,
        refillAmount: 10,
        refillInterval: 1000,
        rateLimitEnabled: false,
        rateLimitTimeWindow: 2000,
        rateLimitMax: 20,
        metadata: {test: "test-123"},
        permissions: {files: ["read", "write"]}
      }
    )

    assert updated[:expiresAt]
    assert_equal 50, updated[:remaining]
    assert_equal 10, updated[:refillAmount]
    assert_equal 1000, updated[:refillInterval]
    assert_equal false, updated[:rateLimitEnabled]
    assert_equal 2000, updated[:rateLimitTimeWindow]
    assert_equal 20, updated[:rateLimitMax]
    assert_equal({"test" => "test-123"}, updated[:metadata])
    assert_equal({"files" => ["read", "write"]}, updated[:permissions])
  end

  def test_update_does_not_touch_usage_fields_unless_explicitly_requested
    auth = build_auth(default_key_length: 12, enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "update-side-effects-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 100})

    renamed = auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], name: "updated-name"})
    assert_nil renamed[:lastRequest]
    assert_equal 100, renamed[:remaining]

    explicit_remaining = auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], remaining: 50})
    assert_nil explicit_remaining[:lastRequest]
    assert_equal 50, explicit_remaining[:remaining]

    verified = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal true, verified[:valid]
    stored = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    assert stored[:lastRequest]
    assert_equal 49, stored[:remaining]
  end

  def test_get_list_and_delete_edge_cases_match_upstream
    auth = build_auth(default_key_length: 12, enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "route-edge-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    first = auth.api.create_api_key(body: {userId: user_id, name: "aaa-sort-test", metadata: {tier: "pro"}, permissions: {files: ["read"]}})
    second = auth.api.create_api_key(body: {userId: user_id, name: "zzz-sort-test"})

    get_missing = assert_raises(BetterAuth::APIError) do
      auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: "invalid"})
    end
    assert_equal "NOT_FOUND", get_missing.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_NOT_FOUND"], get_missing.message

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: first[:id]})
    assert_equal({"tier" => "pro"}, fetched[:metadata])
    assert_equal({"files" => ["read"]}, fetched[:permissions])

    list_without_session = assert_raises(BetterAuth::APIError) { auth.api.list_api_keys }
    assert_equal "UNAUTHORIZED", list_without_session.status

    asc = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {sortBy: "name", sortDirection: "asc", limit: "2", offset: "0"})
    desc = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {sortBy: "name", sortDirection: "desc"})
    overflow = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {offset: asc[:total] + 100})

    assert_equal 2, asc[:limit]
    assert_equal 0, asc[:offset]
    assert_equal %w[aaa-sort-test zzz-sort-test], asc[:apiKeys].map { |entry| entry[:name] }
    assert_equal "zzz-sort-test", desc[:apiKeys].first[:name]
    assert_empty overflow[:apiKeys]
    assert_equal asc[:total], overflow[:total]

    delete_missing = assert_raises(BetterAuth::APIError) do
      auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: "invalid"})
    end
    assert_equal "NOT_FOUND", delete_missing.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_NOT_FOUND"], delete_missing.message

    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: second[:id]}))
  end

  def test_update_ignores_metadata_when_metadata_is_disabled
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "metadata-disabled-update-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})

    updated = auth.api.update_api_key(body: {userId: user_id, keyId: created[:id], name: "renamed", metadata: {tier: "pro"}})

    assert_equal "renamed", updated[:name]
    assert_nil updated[:metadata]
  end

  def test_delete_all_expired_api_keys_returns_upstream_payload_shape
    auth = build_auth(default_key_length: 12)

    result = auth.api.delete_all_expired_api_keys

    assert_equal({success: true, error: nil}, result)
  end

  def test_delete_rejects_banned_users
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.admin,
        BetterAuth::Plugins.api_key(default_key_length: 12)
      ]
    )
    cookie = sign_up_cookie(auth, email: "banned-delete-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id})
    auth.context.internal_adapter.update_user(user_id, banned: true)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_api_key(headers: {"cookie" => cookie}, query: {disableCookieCache: true}, body: {keyId: created[:id]})
    end

    assert_equal "UNAUTHORIZED", error.status
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["USER_BANNED"], error.message
  end

  def test_secondary_storage_requires_configured_storage_backend
    auth = build_auth(default_key_length: 12, storage: "secondary-storage")
    cookie = sign_up_cookie(auth, email: "missing-storage-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {userId: user_id})
    end

    assert_equal "INTERNAL_SERVER_ERROR", error.status
    assert_equal "Secondary storage is required when storage mode is 'secondary-storage'", error.message
  end

  def test_legacy_double_stringified_metadata_is_returned_as_object_and_migrated
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "metadata-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {metadata: {tier: "free"}})
    legacy = JSON.generate(JSON.generate({tier: "legacy"}))

    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {metadata: legacy})

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    assert_equal({"tier" => "legacy"}, fetched[:metadata])

    migrated = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
    assert_equal({"tier" => "legacy"}, JSON.parse(migrated["metadata"]))

    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {metadata: legacy})
    verified = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal({"tier" => "legacy"}, verified[:key][:metadata])
  end

  def test_defer_updates_uses_configured_background_task_handler
    deferred = []
    auth = build_auth(
      defer_updates: true,
      advanced: {
        background_tasks: {
          handler: ->(task) { deferred << task }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "defer-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 2})

    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal true, result[:valid]
    assert_equal 1, result[:key][:remaining]
    assert_equal 1, deferred.length
    stored_before_task = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
    assert_nil stored_before_task["lastRequest"]
    deferred.each(&:call)
    stored_after_task = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
    assert stored_after_task["lastRequest"]
    assert_equal 1, stored_after_task["remaining"]
  end

  def build_auth(options = {})
    advanced = options.is_a?(Hash) ? options.delete(:advanced) : nil
    secondary_storage = options.is_a?(Hash) ? options.delete(:secondary_storage) : nil
    session = options.is_a?(Hash) ? options.delete(:session) : nil
    BetterAuth.auth({
      secret: SECRET,
      email_and_password: {enabled: true},
      advanced: advanced,
      secondary_storage: secondary_storage,
      session: session,
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
    attr_reader :values, :ttls, :get_calls, :set_calls, :delete_calls

    def initialize
      @values = {}
      @ttls = {}
      @get_calls = []
      @set_calls = []
      @delete_calls = []
    end

    def get(key)
      get_calls << key
      values[key]
    end

    def set(key, value, ttl = nil)
      set_calls << [key, value, ttl]
      values[key] = value
      ttls[key] = ttl if ttl
    end

    def delete(key)
      delete_calls << key
      values.delete(key)
      ttls.delete(key)
    end

    def keys
      values.keys
    end

    def clear
      values.clear
      ttls.clear
      get_calls.clear
      set_calls.clear
      delete_calls.clear
    end
  end
end
