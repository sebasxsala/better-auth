# frozen_string_literal: true

require "better_auth"
require_relative "redis_storage/version"

module BetterAuth
  class RedisStorage
    DEFAULT_KEY_PREFIX = "better-auth:"

    attr_reader :client, :key_prefix

    def self.build(client:, key_prefix: DEFAULT_KEY_PREFIX)
      new(client: client, key_prefix: key_prefix)
    end

    def initialize(client:, key_prefix: DEFAULT_KEY_PREFIX)
      @client = client
      @key_prefix = key_prefix.to_s
    end

    def get(key)
      client.get(prefix_key(key))
    end

    def set(key, value, ttl = nil)
      prefixed_key = prefix_key(key)
      if ttl&.to_i&.positive?
        client.setex(prefixed_key, ttl.to_i, value)
      else
        client.set(prefixed_key, value)
      end
    end

    def delete(key)
      client.del(prefix_key(key))
    end

    def list_keys
      client.keys("#{key_prefix}*").map { |key| unprefix_key(key) }
    end

    def clear
      keys = client.keys("#{key_prefix}*")
      client.del(*keys) unless keys.empty?
    end

    alias_method :listKeys, :list_keys

    private

    def prefix_key(key)
      "#{key_prefix}#{key}"
    end

    def unprefix_key(key)
      key.sub(/\A#{Regexp.escape(key_prefix)}/, "")
    end
  end
end
