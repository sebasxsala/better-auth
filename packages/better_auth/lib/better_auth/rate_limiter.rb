# frozen_string_literal: true

require "json"

module BetterAuth
  class RateLimiter
    class MemoryStore
      def initialize
        @entries = {}
        @mutex = Mutex.new
      end

      def get(key)
        @mutex.synchronize do
          entry = @entries[key]
          return nil unless entry

          if Time.now.to_f >= entry[:expires_at]
            @entries.delete(key)
            return nil
          end

          entry[:data]
        end
      end

      def set(key, value, ttl:, update: false)
        @mutex.synchronize do
          @entries[key] = {
            data: value,
            expires_at: Time.now.to_f + ttl.to_f
          }
        end
      end
    end

    def initialize
      @memory_store = MemoryStore.new
    end

    def call(request, context, path)
      config = context.rate_limit_config || {}
      return unless config[:enabled]

      rule = matching_plugin_rule(context, path)
      window = (rule && rule[:window]) || config[:window] || 10
      max = (rule && rule[:max]) || config[:max] || 100
      key = rate_limit_key(request.ip, path)
      now = Time.now.to_f
      storage = storage_for(context, config)
      data = read_storage(storage, key)

      unless data
        write_storage(storage, key, rate_limit_data(key, 1, now), ttl: window, update: false)
        return
      end

      last_request = data.fetch(:last_request).to_f
      count = data.fetch(:count).to_i
      if should_rate_limit?(max.to_i, window.to_f, count, last_request, now)
        return rate_limit_response(retry_after(last_request, window.to_f, now))
      end

      next_data = if now - last_request > window.to_f
        rate_limit_data(key, 1, now)
      else
        rate_limit_data(key, count + 1, now)
      end

      write_storage(storage, key, next_data, ttl: window, update: true)
      nil
    end

    private

    def rate_limit_response(retry_after)
      [
        429,
        {"content-type" => "application/json", "x-retry-after" => retry_after.to_s},
        [JSON.generate({message: "Too many requests. Please try again later."})]
      ]
    end

    def should_rate_limit?(max, window, count, last_request, now)
      now - last_request < window && count >= max
    end

    def retry_after(last_request, window, now)
      [(last_request + window - now).ceil, 0].max
    end

    def rate_limit_data(key, count, last_request)
      {
        key: key,
        count: count,
        last_request: last_request
      }
    end

    def storage_for(context, config)
      return [:custom, config[:custom_storage]] if config[:custom_storage]

      if config[:storage] == "secondary-storage" && context.options.secondary_storage
        return [:secondary, context.options.secondary_storage]
      end

      [:memory, @memory_store]
    end

    def read_storage((type, storage), key)
      data = storage.get(key)
      data = JSON.parse(data) if type == :secondary && data.is_a?(String)
      symbolize_keys(data)
    rescue JSON::ParserError
      nil
    end

    def write_storage((type, storage), key, data, ttl:, update:)
      value = (type == :secondary) ? JSON.generate(data) : data
      return call_secondary_storage_set(storage, key, value, ttl: ttl, update: update) if type == :secondary

      call_storage_set(storage, key, value, ttl: ttl, update: update)
    end

    def call_secondary_storage_set(storage, key, value, ttl:, update:)
      storage.set(key, value, ttl)
    rescue ArgumentError
      call_storage_set(storage, key, value, ttl: ttl, update: update)
    end

    def call_storage_set(storage, key, value, ttl:, update:)
      storage.set(key, value, ttl: ttl, update: update)
    rescue ArgumentError
      begin
        storage.set(key, value, ttl, update)
      rescue ArgumentError
        begin
          storage.set(key, value, ttl)
        rescue ArgumentError
          storage.set(key, value)
        end
      end
    end

    def symbolize_keys(value)
      return value unless value.is_a?(Hash)

      value.each_with_object({}) do |(key, object_value), result|
        result[key.to_s.gsub(/([a-z\d])([A-Z])/, "\\1_\\2").tr("-", "_").downcase.to_sym] = object_value
      end
    end

    def rate_limit_key(ip, path)
      "#{ip}|#{path}"
    end

    def matching_plugin_rule(context, path)
      context.options.plugins
        .flat_map { |plugin| Array(plugin[:rate_limit]) }
        .find do |rule|
          matcher = rule[:path_matcher]
          matcher&.call(path)
        end
    end
  end
end
