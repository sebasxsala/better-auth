# frozen_string_literal: true

require "json"
require "securerandom"
require "stringio"
require "test_helper"

class RedisStorageIntegrationTest < Minitest::Test
  def setup
    skip "set REDIS_INTEGRATION=1 to run real Redis integration" unless ENV["REDIS_INTEGRATION"] == "1"

    redis_url = ENV["REDIS_URL"] || "redis://localhost:6379/15"
    require "redis"
    @client = Redis.new(url: redis_url)
    @client.ping
    @prefix_root = "better-auth-test:#{SecureRandom.hex(6)}"
    @storage = BetterAuth::RedisStorage.new(client: @client, key_prefix: "#{@prefix_root}:")
    @storage.clear
  rescue LoadError
    skip "redis gem is not available"
  rescue => error
    raise unless defined?(Redis::BaseConnectionError) && error.is_a?(Redis::BaseConnectionError)

    skip "Redis is not reachable at #{redis_url}"
  end

  def teardown
    @storage&.clear
    @client&.del("#{@prefix_root}:outside") if @client && @prefix_root
    @client&.close if @client.respond_to?(:close)
  end

  def test_real_redis_round_trip_on_get_set_delete
    @storage.set("a", "one")
    @storage.set("b", "two", 60)

    assert_equal "one", @storage.get("a")
    assert_equal "two", @storage.get("b")

    @storage.delete("a")

    assert_nil @storage.get("a")
  end

  def test_real_redis_session_storage_for_database_and_secondary_only_modes
    @client.set("#{@prefix_root}:outside", "outside")

    [false, true].each do |store_session_in_database|
      storage = BetterAuth::RedisStorage.new(
        client: @client,
        key_prefix: "#{@prefix_root}:#{store_session_in_database}:"
      )
      storage.clear
      auth = build_auth(storage, store_session_in_database: store_session_in_database)

      result = auth.api.sign_up_email(
        body: {
          email: "redis-#{store_session_in_database}-#{SecureRandom.hex(4)}@example.com",
          password: "password123",
          name: "Redis User"
        }
      )

      assert result[:token]
      keys = storage.listKeys
      refute_empty keys
      refute_includes keys, "#{@prefix_root}:outside"
      session_key = keys.find { |key| !key.start_with?("active-sessions-") }
      session_data = JSON.parse(storage.get(session_key))
      assert session_data.fetch("user").fetch("id")
      assert session_data.fetch("session").fetch("id")
      assert_equal result[:token], session_data.fetch("session").fetch("token")
    ensure
      storage&.clear
    end
  end

  def test_real_redis_rate_limiting_persists_under_secondary_storage
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: @storage,
      rate_limit: {storage: "secondary-storage", enabled: true, max: 1, window: 60},
      plugins: [
        {
          id: "redis-storage-integration",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/limited")).first

    key = @storage.list_keys.find { |entry| entry == "127.0.0.1|/limited" }
    refute_nil key
    stored = JSON.parse(@storage.get(key))
    assert_equal 1, stored.fetch("count")
  end

  private

  def build_auth(storage, store_session_in_database:)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: "redis-storage-secret-with-enough-entropy-12345",
      database: :memory,
      secondary_storage: storage,
      email_and_password: {enabled: true},
      session: {store_session_in_database: store_session_in_database}
    )
  end

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
end
