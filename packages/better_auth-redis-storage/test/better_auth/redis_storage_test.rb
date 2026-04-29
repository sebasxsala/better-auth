# frozen_string_literal: true

require "stringio"
require "test_helper"

class RedisStorageTest < Minitest::Test
  # Real Redis coverage lives in redis_storage_integration_test.rb and is gated
  # by REDIS_INTEGRATION=1.

  def setup
    @client = FakeRedisClient.new
    @storage = BetterAuth::RedisStorage.new(client: @client)
  end

  def test_set_and_get_use_default_key_prefix
    @storage.set("session-token", "payload")

    assert_equal "payload", @storage.get("session-token")
    assert_equal "payload", @client.data.fetch("better-auth:session-token")
  end

  def test_nil_key_prefix_uses_default_prefix
    storage = BetterAuth::RedisStorage.new(client: @client, key_prefix: nil)

    storage.set("session-token", "payload")

    assert_equal "payload", @client.data.fetch("better-auth:session-token")
  end

  def test_set_with_positive_ttl_uses_setex
    result = @storage.set("rate-limit", "payload", 60)

    assert_nil result
    assert_equal [["better-auth:rate-limit", 60, "payload"]], @client.setex_calls
  end

  def test_set_with_zero_or_nil_ttl_uses_plain_set
    @storage.set("without-ttl", "one", nil)
    @storage.set("zero-ttl", "two", 0)

    assert_equal [["better-auth:without-ttl", "one"], ["better-auth:zero-ttl", "two"]], @client.set_calls
  end

  def test_set_treats_string_ttl_as_seconds_when_positive
    @storage.set("string-ttl", "payload", "60")

    assert_equal [["better-auth:string-ttl", 60, "payload"]], @client.setex_calls
  end

  def test_set_falls_back_to_plain_set_for_non_numeric_or_negative_ttl
    @storage.set("bad-ttl", "payload", "abc")
    @storage.set("partial-ttl", "payload", "60abc")
    @storage.set("neg-ttl", "payload", -5)
    @storage.set("float-zero-ttl", "payload", 0.0)

    assert_equal [
      ["better-auth:bad-ttl", "payload"],
      ["better-auth:partial-ttl", "payload"],
      ["better-auth:neg-ttl", "payload"],
      ["better-auth:float-zero-ttl", "payload"]
    ], @client.set_calls
  end

  def test_set_with_float_positive_ttl_truncates_to_integer
    @storage.set("float-ttl", "payload", 1.9)

    assert_equal [["better-auth:float-ttl", 1, "payload"]], @client.setex_calls
  end

  def test_delete_removes_prefixed_key
    @storage.set("session-token", "payload")
    result = @storage.delete("session-token")

    assert_nil result
    refute @client.data.key?("better-auth:session-token")
  end

  def test_list_keys_returns_unprefixed_keys_for_configured_prefix
    storage = BetterAuth::RedisStorage.new(client: @client, key_prefix: "auth:")
    storage.set("a", "one")
    storage.set("nested:b", "two")
    @client.set("other:c", "three")

    assert_equal ["a", "nested:b"], storage.list_keys.sort
  end

  def test_clear_deletes_only_prefixed_keys
    @storage.set("a", "one")
    @storage.set("b", "two")
    @client.set("other:c", "three")

    result = @storage.clear

    assert_nil result
    assert_empty @storage.list_keys
    assert_equal "three", @client.get("other:c")
  end

  def test_clear_does_not_call_del_when_no_keys_match
    result = @storage.clear

    assert_nil result
    assert_empty @client.del_calls
  end

  def test_list_keys_preserves_public_write_order
    @storage.set("first", "one")
    @storage.set("second", "two")
    @storage.set("third", "three")

    assert_equal ["first", "second", "third"], @storage.list_keys
  end

  def test_prefixed_storage_never_bleeds_into_unprefixed_keys
    storage = BetterAuth::RedisStorage.new(client: @client, key_prefix: "auth:")
    storage.set("session", "inside")
    @client.set("session", "outside")

    assert_equal ["session"], storage.list_keys
    assert_equal "inside", storage.get("session")
    assert_equal "outside", @client.get("session")
  end

  def test_list_keys_uses_scan_when_scan_count_is_provided
    scan_client = ScanCapableFakeRedisClient.new
    scan_client.set("better-auth:a", "one")
    scan_client.set("better-auth:b", "two")
    scan_client.set("other:c", "three")

    storage = BetterAuth::RedisStorage.new(client: scan_client, scan_count: 50)

    assert_equal ["a", "b"], storage.list_keys.sort
    assert_empty scan_client.keys_calls
    assert_equal [["0", {match: "better-auth:*", count: 50}]], scan_client.scan_calls.first(1)
  end

  def test_build_returns_storage_instance
    storage = BetterAuth::RedisStorage.build(client: @client)

    assert_instance_of BetterAuth::RedisStorage, storage
  end

  def test_module_level_redis_storage_builder_returns_storage_instance
    storage = BetterAuth.redis_storage(client: @client, key_prefix: "auth:")

    assert_instance_of BetterAuth::RedisStorage, storage
    assert_equal "auth:", storage.key_prefix

    storage.set("k", "v")
    assert_equal "v", @client.data.fetch("auth:k")
  end

  def test_camel_case_redis_storage_class_method_alias_matches_upstream_name
    storage = BetterAuth::RedisStorage.redisStorage(client: @client)

    assert_instance_of BetterAuth::RedisStorage, storage
  end

  def test_camel_case_list_keys_alias_matches_upstream_name
    @storage.set("a", "one")

    assert_equal ["a"], @storage.listKeys
  end

  def test_secondary_storage_can_back_session_payload_when_session_not_in_database
    storage = BetterAuth::RedisStorage.new(client: FakeRedisClient.new)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: storage,
      email_and_password: {enabled: true},
      session: {store_session_in_database: false}
    )

    result = auth.api.sign_up_email(
      body: {email: "session-fake@example.com", password: "password123", name: "Fake User"}
    )

    assert result[:token]
    assert storage.get("active-sessions-#{result[:user]["id"]}")
    session_keys = storage.list_keys.reject { |key| key.start_with?("active-sessions-") }
    assert_equal 1, session_keys.length
    parsed = JSON.parse(storage.get(session_keys.first))
    assert_equal result[:token], parsed.fetch("session").fetch("token")
  end

  def test_secondary_storage_can_back_rate_limiting
    storage = BetterAuth::RedisStorage.new(client: FakeRedisClient.new)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: storage,
      rate_limit: {storage: "secondary-storage", enabled: true, max: 1, window: 60},
      plugins: [
        {
          id: "redis-storage-test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/limited")).first

    rate_limit_keys = storage.list_keys.select { |key| key == "127.0.0.1|/limited" }
    refute_empty rate_limit_keys
    parsed = JSON.parse(storage.get(rate_limit_keys.first))
    assert_equal ["count", "key", "lastRequest"], parsed.keys.sort
  end

  def test_secondary_storage_can_back_verification_values
    storage = BetterAuth::RedisStorage.new(client: FakeRedisClient.new)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: storage,
      email_and_password: {enabled: true},
      session: {store_session_in_database: false}
    )

    verification = auth.context.internal_adapter.create_verification_value(
      identifier: "verify-redis",
      value: "secret",
      expiresAt: Time.now + 120
    )

    assert verification["id"]
    assert storage.get("verification:verify-redis")
    assert storage.get("verification-id:#{verification["id"]}")
    assert_equal "secret", auth.context.internal_adapter.find_verification_value("verify-redis")["value"]
  end

  private

  def rack_env(method, path)
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(""),
      "CONTENT_LENGTH" => "0"
    }
  end

  class FakeRedisClient
    attr_reader :data, :set_calls, :setex_calls, :del_calls, :keys_calls

    def initialize
      @data = {}
      @set_calls = []
      @setex_calls = []
      @del_calls = []
      @keys_calls = []
    end

    def get(key)
      data[key]
    end

    def set(key, value)
      set_calls << [key, value]
      data[key] = value
    end

    def setex(key, ttl, value)
      setex_calls << [key, ttl, value]
      data[key] = value
    end

    def del(*keys)
      del_calls << keys
      keys.each { |key| data.delete(key) }
    end

    def keys(pattern)
      keys_calls << pattern
      regex = Regexp.new("\\A#{Regexp.escape(pattern).gsub("\\*", ".*")}\\z")
      data.keys.select { |key| regex.match?(key) }
    end
  end

  class ScanCapableFakeRedisClient < FakeRedisClient
    attr_reader :scan_calls

    def initialize
      super
      @scan_calls = []
    end

    def scan(cursor, match:, count:)
      scan_calls << [cursor, {match: match, count: count}]
      matching = keys_without_tracking(match)
      midpoint = (matching.length / 2.0).ceil
      if cursor == "0" && matching.length > midpoint
        ["1", matching.first(midpoint)]
      else
        ["0", matching.drop((cursor == "0") ? 0 : midpoint)]
      end
    end

    private

    def keys_without_tracking(pattern)
      regex = Regexp.new("\\A#{Regexp.escape(pattern).gsub("\\*", ".*")}\\z")
      data.keys.select { |key| regex.match?(key) }
    end
  end
end
