# frozen_string_literal: true

require "securerandom"
require "test_helper"

class RedisStorageTest < Minitest::Test
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

  def test_build_returns_storage_instance
    storage = BetterAuth::RedisStorage.build(client: @client)

    assert_instance_of BetterAuth::RedisStorage, storage
  end

  def test_camel_case_list_keys_alias_matches_upstream_name
    @storage.set("a", "one")

    assert_equal ["a"], @storage.listKeys
  end

  def test_real_redis_stores_better_auth_sessions_with_prefix_isolation
    redis_url = ENV["REDIS_URL"]
    skip "set REDIS_URL to run real Redis integration" if redis_url.to_s.empty?

    begin
      require "redis"
      redis_connected = false
      client = Redis.new(url: redis_url)
      client.ping
      redis_connected = true
    rescue LoadError
      skip "redis gem is not available"
    rescue Redis::BaseConnectionError
      skip "Redis is not reachable at REDIS_URL"
    end

    prefix_root = "better-auth-test:#{SecureRandom.hex(6)}"
    client.set("#{prefix_root}:other:session", "outside")

    [false, true].each do |store_session_in_database|
      key_prefix = "#{prefix_root}:#{store_session_in_database}:"
      storage = BetterAuth::RedisStorage.new(client: client, key_prefix: key_prefix)
      storage.clear
      auth = BetterAuth.auth(
        base_url: "http://localhost:3000",
        secret: "redis-storage-secret-with-enough-entropy-123",
        database: :memory,
        secondary_storage: storage,
        session: {store_session_in_database: store_session_in_database}
      )

      result = auth.api.sign_up_email(
        body: {
          email: "redis-#{store_session_in_database}@example.com",
          password: "password123",
          name: "Redis User"
        }
      )

      assert result[:token]
      keys = storage.listKeys
      assert_equal 2, keys.length
      refute_includes keys, "#{prefix_root}:other:session"
      session_key = keys.find { |key| !key.start_with?("active-sessions-") }
      session_data = JSON.parse(storage.get(session_key))
      assert session_data.fetch("user").fetch("id")
      assert session_data.fetch("session").fetch("id")
      assert_equal result[:token], session_data.fetch("session").fetch("token")
    ensure
      storage&.clear
    end
  ensure
    client&.del("#{prefix_root}:other:session") if defined?(client) && client && redis_connected
    client&.close if defined?(client) && client.respond_to?(:close) && redis_connected
  end

  class FakeRedisClient
    attr_reader :data, :set_calls, :setex_calls, :del_calls

    def initialize
      @data = {}
      @set_calls = []
      @setex_calls = []
      @del_calls = []
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
      regex = Regexp.new("\\A#{Regexp.escape(pattern).gsub("\\*", ".*")}\\z")
      data.keys.select { |key| regex.match?(key) }
    end
  end
end
