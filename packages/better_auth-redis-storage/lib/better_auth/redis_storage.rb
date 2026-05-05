# frozen_string_literal: true

require "better_auth"
require_relative "redis_storage/version"

module BetterAuth
  def self.redis_storage(client:, key_prefix: RedisStorage::DEFAULT_KEY_PREFIX, scan_count: nil)
    RedisStorage.new(client: client, key_prefix: key_prefix, scan_count: scan_count)
  end

  class RedisStorage
    DEFAULT_KEY_PREFIX = "better-auth:"
    SCAN_DEFAULT_COUNT = 100
    DELETE_CHUNK_SIZE = 500

    attr_reader :client, :key_prefix, :scan_count

    def self.build(client:, key_prefix: DEFAULT_KEY_PREFIX, scan_count: nil)
      new(client: client, key_prefix: key_prefix, scan_count: scan_count)
    end

    def self.redisStorage(client:, key_prefix: DEFAULT_KEY_PREFIX, scan_count: nil)
      new(client: client, key_prefix: key_prefix, scan_count: scan_count)
    end

    def initialize(client:, key_prefix: DEFAULT_KEY_PREFIX, scan_count: nil)
      @client = client
      @key_prefix = key_prefix.nil? ? DEFAULT_KEY_PREFIX : key_prefix.to_s
      if !scan_count.nil? && !(scan_count.is_a?(Integer) && scan_count.positive?)
        raise ArgumentError, "scan_count must be nil or a positive Integer; got #{scan_count.inspect}"
      end
      @scan_count = scan_count
    end

    def get(key)
      client.get(prefix_key(key))
    end

    def set(key, value, ttl = nil)
      prefixed_key = prefix_key(key)
      coerced_ttl = coerce_ttl(ttl)
      if coerced_ttl
        client.setex(prefixed_key, coerced_ttl, value)
      else
        client.set(prefixed_key, value)
      end
      nil
    end

    def delete(key)
      client.del(prefix_key(key))
      nil
    end

    def list_keys
      storage_keys.map { |key| unprefix_key(key) }
    end

    def clear
      keys = storage_keys
      # Upstream calls del(...keys) unconditionally; Ruby keeps this guard to
      # avoid Redis ERR wrong number of arguments when no prefixed keys exist.
      keys.each_slice(DELETE_CHUNK_SIZE) { |chunk| client.del(*chunk) }
      nil
    end

    alias_method :listKeys, :list_keys

    private

    def prefix_key(key)
      raise ArgumentError, "secondary storage key must not be nil" if key.nil?

      "#{key_prefix}#{key}"
    end

    def unprefix_key(key)
      key.sub(/\A#{Regexp.escape(key_prefix)}/, "")
    end

    def storage_keys
      return scan_keys if scan_count

      client.keys("#{key_prefix}*")
    end

    def scan_keys
      cursor = "0"
      matches = []
      loop do
        cursor, keys = client.scan(cursor, match: "#{key_prefix}*", count: scan_count)
        matches.concat(keys)
        break if cursor.to_s == "0"
      end
      matches
    end

    def coerce_ttl(ttl)
      numeric = case ttl
      when nil
        nil
      when Integer
        ttl
      when Float
        ttl.finite? ? ttl : nil
      when String
        Integer(ttl, exception: false)
      when Numeric
        ttl.to_f
      end

      return nil unless numeric.is_a?(Numeric)
      return nil unless numeric.respond_to?(:positive?) && numeric.positive?
      return nil if numeric.respond_to?(:finite?) && !numeric.finite?

      numeric.is_a?(Integer) ? numeric : numeric.to_i
    end
  end
end
