# frozen_string_literal: true

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

  def test_set_with_positive_ttl_uses_setex
    @storage.set("rate-limit", "payload", 60)

    assert_equal [["better-auth:rate-limit", 60, "payload"]], @client.setex_calls
  end

  def test_set_with_zero_or_nil_ttl_uses_plain_set
    @storage.set("without-ttl", "one", nil)
    @storage.set("zero-ttl", "two", 0)

    assert_equal [["better-auth:without-ttl", "one"], ["better-auth:zero-ttl", "two"]], @client.set_calls
  end

  def test_delete_removes_prefixed_key
    @storage.set("session-token", "payload")
    @storage.delete("session-token")

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

    @storage.clear

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
