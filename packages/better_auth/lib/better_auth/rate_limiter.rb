# frozen_string_literal: true

require "ipaddr"
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

      ip = client_ip(request, context.options)
      return unless ip

      rule = rate_limit_rule(request, context, config, path)
      return if rule == false

      window = rule[:window] || 10
      max = rule[:max] || 100
      key = rate_limit_key(ip, path)
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

    def rate_limit_rule(request, context, config, path)
      rule = {
        window: config[:window] || 10,
        max: config[:max] || 100
      }
      rule = default_special_rule(path) || rule
      rule = matching_plugin_rule(context, path) || rule
      custom_rule = matching_custom_rule(config, path)
      return resolve_custom_rule(custom_rule, request, rule) unless custom_rule.nil?

      rule
    end

    def default_special_rule(path)
      return unless path.start_with?("/sign-in", "/sign-up", "/change-password", "/change-email")

      {window: 10, max: 3}
    end

    def matching_custom_rule(config, path)
      custom_rules = config[:custom_rules] || {}
      custom_rules.find do |pattern, _rule|
        path_matches?(pattern.to_s, path)
      end&.last
    end

    def resolve_custom_rule(rule, request, current)
      return false if rule == false
      return rule.call(request, current) if rule.respond_to?(:call)

      rule || current
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

    def client_ip(request, options)
      ip_options = options.advanced[:ip_address] || {}
      return if ip_options[:disable_ip_tracking]

      Array(ip_options[:ip_address_headers] || ["x-forwarded-for"]).each do |header|
        value = request.get_header(rack_header_name(header))
        next unless value.is_a?(String)

        ip = value.split(",").first.to_s.strip
        return normalize_ip(ip, ipv6_subnet: ip_options[:ipv6_subnet]) if valid_ip?(ip)
      end

      ip = request.ip.to_s
      normalize_ip(ip, ipv6_subnet: ip_options[:ipv6_subnet]) if valid_ip?(ip)
    end

    def rack_header_name(header)
      "HTTP_#{header.to_s.upcase.tr("-", "_")}"
    end

    def valid_ip?(ip)
      return false if ip.empty? || ip.match?(/\s/)

      IPAddr.new(ip)
      true
    rescue ArgumentError
      false
    end

    def normalize_ip(ip, ipv6_subnet: nil)
      address = IPAddr.new(ip)
      return address.native.to_s if address.respond_to?(:ipv4_mapped?) && address.ipv4_mapped?
      return address.to_s if address.ipv4?

      address.mask((ipv6_subnet || 64).to_i).to_s
    end

    def matching_plugin_rule(context, path)
      context.options.plugins
        .flat_map { |plugin| Array(plugin[:rate_limit]) }
        .find do |rule|
          matcher = rule[:path_matcher]
          matcher&.call(path)
        end
    end

    def path_matches?(pattern, path)
      return path == pattern unless pattern.include?("*")

      regex = Regexp.escape(pattern).gsub("\\*", ".*")
      /\A#{regex}\z/.match?(path)
    end
  end
end
