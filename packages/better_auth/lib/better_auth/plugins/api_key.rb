# frozen_string_literal: true

require "json"
require "securerandom"
require "time"

module BetterAuth
  module Plugins
    API_KEY_ERROR_CODES = {
      "INVALID_METADATA_TYPE" => "metadata must be an object or undefined",
      "REFILL_AMOUNT_AND_INTERVAL_REQUIRED" => "refillAmount is required when refillInterval is provided",
      "REFILL_INTERVAL_AND_AMOUNT_REQUIRED" => "refillInterval is required when refillAmount is provided",
      "USER_BANNED" => "User is banned",
      "UNAUTHORIZED_SESSION" => "Unauthorized or invalid session",
      "KEY_NOT_FOUND" => "API Key not found",
      "KEY_DISABLED" => "API Key is disabled",
      "KEY_EXPIRED" => "API Key has expired",
      "USAGE_EXCEEDED" => "API Key has reached its usage limit",
      "KEY_NOT_RECOVERABLE" => "API Key is not recoverable",
      "EXPIRES_IN_IS_TOO_SMALL" => "The expiresIn is smaller than the predefined minimum value.",
      "EXPIRES_IN_IS_TOO_LARGE" => "The expiresIn is larger than the predefined maximum value.",
      "INVALID_REMAINING" => "The remaining count is either too large or too small.",
      "INVALID_PREFIX_LENGTH" => "The prefix length is either too large or too small.",
      "INVALID_NAME_LENGTH" => "The name length is either too large or too small.",
      "METADATA_DISABLED" => "Metadata is disabled.",
      "RATE_LIMIT_EXCEEDED" => "Rate limit exceeded.",
      "NO_VALUES_TO_UPDATE" => "No values to update.",
      "KEY_DISABLED_EXPIRATION" => "Custom key expiration values are disabled.",
      "INVALID_API_KEY" => "Invalid API key.",
      "INVALID_USER_ID_FROM_API_KEY" => "The user id from the API key is invalid.",
      "INVALID_API_KEY_GETTER_RETURN_TYPE" => "API Key getter returned an invalid key type. Expected string.",
      "SERVER_ONLY_PROPERTY" => "The property you're trying to set can only be set from the server auth instance only.",
      "FAILED_TO_UPDATE_API_KEY" => "Failed to update API key",
      "NAME_REQUIRED" => "API Key name is required."
    }.freeze

    API_KEY_TABLE_NAME = "apikey"

    module_function

    def api_key(options = {})
      config = api_key_config(options)
      Plugin.new(
        id: "api-key",
        hooks: {
          before: [
            {
              matcher: ->(ctx) { config[:enable_session_for_api_keys] && !!api_key_get_from_headers(ctx, config) },
              handler: ->(ctx) { api_key_session_hook(ctx, config) }
            }
          ]
        },
        endpoints: {
          create_api_key: api_key_create_endpoint(config),
          verify_api_key: api_key_verify_endpoint(config),
          get_api_key: api_key_get_endpoint(config),
          update_api_key: api_key_update_endpoint(config),
          delete_api_key: api_key_delete_endpoint(config),
          list_api_keys: api_key_list_endpoint(config),
          delete_all_expired_api_keys: api_key_delete_expired_endpoint(config)
        },
        schema: api_key_schema(config, config[:schema]),
        error_codes: API_KEY_ERROR_CODES,
        options: config
      )
    end

    def api_key_config(options)
      data = normalize_hash(options)
      rate_limit_options = data[:rate_limit] || {}
      starting_characters_options = data[:starting_characters_config] || {}
      {
        api_key_headers: data[:api_key_headers] || "x-api-key",
        default_key_length: data[:default_key_length] || 64,
        maximum_prefix_length: data.key?(:maximum_prefix_length) ? data[:maximum_prefix_length] : 32,
        minimum_prefix_length: data.key?(:minimum_prefix_length) ? data[:minimum_prefix_length] : 1,
        maximum_name_length: data.key?(:maximum_name_length) ? data[:maximum_name_length] : 32,
        minimum_name_length: data.key?(:minimum_name_length) ? data[:minimum_name_length] : 1,
        enable_metadata: data[:enable_metadata] || false,
        disable_key_hashing: data[:disable_key_hashing] || false,
        require_name: data[:require_name] || false,
        storage: data[:storage] || "database",
        rate_limit: {
          enabled: rate_limit_options.fetch(:enabled, true),
          time_window: rate_limit_options[:time_window] || 86_400_000,
          max_requests: rate_limit_options[:max_requests] || 10
        },
        key_expiration: {
          default_expires_in: data.dig(:key_expiration, :default_expires_in),
          disable_custom_expires_time: data.dig(:key_expiration, :disable_custom_expires_time) || false,
          max_expires_in: data.dig(:key_expiration, :max_expires_in) || 365,
          min_expires_in: data.dig(:key_expiration, :min_expires_in) || 1
        },
        starting_characters_config: {
          should_store: starting_characters_options.fetch(:should_store, true),
          characters_length: starting_characters_options[:characters_length] || 6
        },
        enable_session_for_api_keys: data[:enable_session_for_api_keys] || false,
        fallback_to_database: data[:fallback_to_database] || false,
        custom_storage: data[:custom_storage],
        custom_key_generator: data[:custom_key_generator],
        custom_api_key_getter: data[:custom_api_key_getter],
        custom_api_key_validator: data[:custom_api_key_validator],
        default_permissions: data[:default_permissions],
        defer_updates: data[:defer_updates] || false,
        schema: data[:schema]
      }
    end

    def api_key_schema(config, custom_schema = nil)
      base = {
        apikey: {
          fields: {
            name: {type: "string", required: false},
            start: {type: "string", required: false},
            prefix: {type: "string", required: false},
            key: {type: "string", required: true, index: true},
            userId: {type: "string", required: true, index: true, references: {model: "user", field: "id", on_delete: "cascade"}},
            refillInterval: {type: "number", required: false},
            refillAmount: {type: "number", required: false},
            lastRefillAt: {type: "date", required: false},
            enabled: {type: "boolean", required: false, default_value: true},
            rateLimitEnabled: {type: "boolean", required: false, default_value: true},
            rateLimitTimeWindow: {type: "number", required: false, default_value: config[:rate_limit][:time_window]},
            rateLimitMax: {type: "number", required: false, default_value: config[:rate_limit][:max_requests]},
            requestCount: {type: "number", required: false, default_value: 0},
            remaining: {type: "number", required: false},
            lastRequest: {type: "date", required: false},
            expiresAt: {type: "date", required: false},
            createdAt: {type: "date", required: true},
            updatedAt: {type: "date", required: true},
            permissions: {type: "string", required: false},
            metadata: {type: "string", required: false}
          }
        }
      }
      deep_merge_hashes(base, normalize_hash(custom_schema || {}))
    end

    def api_key_create_endpoint(config)
      Endpoint.new(path: "/api-key/create", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        session = Routes.current_session(ctx, allow_nil: true)
        if session && body[:user_id]
          raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"])
        end

        user_id = body[:user_id] || session&.dig(:user, "id")
        raise APIError.new("UNAUTHORIZED", message: API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"]) unless user_id

        api_key_validate_create_update!(body, config, create: true, client: !!session)
        key = api_key_generate_key(config, body[:prefix])
        now = Time.now
        hashed = api_key_hash(key, config)
        data = {
          name: body[:name],
          start: config[:starting_characters_config][:should_store] ? key[0, config[:starting_characters_config][:characters_length].to_i] : nil,
          prefix: body[:prefix],
          key: hashed,
          userId: user_id,
          enabled: true,
          rateLimitEnabled: body.key?(:rate_limit_enabled) ? body[:rate_limit_enabled] : config[:rate_limit][:enabled],
          rateLimitTimeWindow: body[:rate_limit_time_window] || config[:rate_limit][:time_window],
          rateLimitMax: body[:rate_limit_max] || config[:rate_limit][:max_requests],
          requestCount: 0,
          remaining: body.key?(:remaining) ? body[:remaining] : (body[:refill_amount] || nil),
          refillAmount: body[:refill_amount],
          refillInterval: body[:refill_interval],
          lastRefillAt: now,
          expiresAt: api_key_expires_at(body, config),
          createdAt: now,
          updatedAt: now,
          permissions: api_key_encode_json(body[:permissions] || config[:default_permissions]),
          metadata: body.key?(:metadata) ? api_key_encode_json(body[:metadata]) : nil
        }
        record = api_key_store(ctx, data, config)
        api_key_public(record, reveal_key: key, include_key_field: true)
      end
    end

    def api_key_verify_endpoint(config)
      Endpoint.new(path: "/api-key/verify", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        key = body[:key] || api_key_get_from_headers(ctx, config)
        raise APIError.new("FORBIDDEN", message: API_KEY_ERROR_CODES["INVALID_API_KEY"]) if key.to_s.empty?

        record = api_key_validate!(ctx, key, config, permissions: body[:permissions])
        api_key_delete_expired(ctx.context, config)
        ctx.json({valid: true, key: api_key_public(record, include_key_field: false)})
      end
    end

    def api_key_get_endpoint(config)
      Endpoint.new(path: "/api-key/get", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        id = normalize_hash(ctx.query)[:id]
        record = api_key_find_by_id(ctx, id, config)
        raise APIError.new("NOT_FOUND", message: API_KEY_ERROR_CODES["KEY_NOT_FOUND"]) unless record && record["userId"] == session[:user]["id"]

        record = api_key_migrate_legacy_metadata(ctx, record, config)
        api_key_delete_expired(ctx.context, config)
        ctx.json(api_key_public(record, include_key_field: false))
      end
    end

    def api_key_update_endpoint(config)
      Endpoint.new(path: "/api-key/update", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        session = Routes.current_session(ctx, allow_nil: true)
        user_id = session&.dig(:user, "id") || body[:user_id]
        raise APIError.new("UNAUTHORIZED", message: API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"]) unless user_id
        if session && body[:user_id] && body[:user_id] != session[:user]["id"]
          raise APIError.new("UNAUTHORIZED", message: API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"])
        end

        key_id = body[:key_id]
        record = api_key_find_by_id(ctx, key_id, config)
        raise APIError.new("NOT_FOUND", message: API_KEY_ERROR_CODES["KEY_NOT_FOUND"]) unless record
        raise APIError.new("NOT_FOUND", message: API_KEY_ERROR_CODES["KEY_NOT_FOUND"]) if record["userId"] != user_id

        api_key_validate_create_update!(body, config, create: false, client: !!session)
        update = api_key_update_payload(body, config)
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["NO_VALUES_TO_UPDATE"]) if update.empty?

        updated = api_key_update_record(ctx, record, update.merge(updatedAt: Time.now), config)
        updated = api_key_migrate_legacy_metadata(ctx, updated, config)
        api_key_delete_expired(ctx.context, config)
        ctx.json(api_key_public(updated, include_key_field: false))
      end
    end

    def api_key_delete_endpoint(config)
      Endpoint.new(path: "/api-key/delete", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        key_id = normalize_hash(ctx.body)[:key_id]
        record = api_key_find_by_id(ctx, key_id, config)
        raise APIError.new("NOT_FOUND", message: API_KEY_ERROR_CODES["KEY_NOT_FOUND"]) unless record && record["userId"] == session[:user]["id"]

        api_key_delete_record(ctx, record, config)
        api_key_delete_expired(ctx.context, config)
        ctx.json({success: true})
      end
    end

    def api_key_list_endpoint(config)
      Endpoint.new(path: "/api-key/list", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        api_key_delete_expired(ctx.context, config)
        ctx.json(api_key_list_for_user(ctx, session[:user]["id"], config).map { |record| api_key_public(api_key_migrate_legacy_metadata(ctx, record, config), include_key_field: false) })
      end
    end

    def api_key_delete_expired_endpoint(config)
      Endpoint.new(path: "/api-key/delete-all-expired-api-keys", method: "POST") do |ctx|
        api_key_delete_expired(ctx.context, config)
        ctx.json({success: true})
      end
    end

    def api_key_session_hook(ctx, config)
      key = api_key_get_from_headers(ctx, config)
      unless key.is_a?(String)
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["INVALID_API_KEY_GETTER_RETURN_TYPE"])
      end
      raise APIError.new("FORBIDDEN", message: API_KEY_ERROR_CODES["INVALID_API_KEY"]) if key.length < config[:default_key_length].to_i

      if config[:custom_api_key_validator].respond_to?(:call) && !config[:custom_api_key_validator].call({ctx: ctx, key: key})
        raise APIError.new("FORBIDDEN", message: API_KEY_ERROR_CODES["INVALID_API_KEY"])
      end

      record = api_key_validate!(ctx, key, config)
      user = ctx.context.internal_adapter.find_user_by_id(record["userId"])
      raise APIError.new("UNAUTHORIZED", message: API_KEY_ERROR_CODES["INVALID_USER_ID_FROM_API_KEY"]) unless user

      session = {
        user: user,
        session: {
          "id" => record["id"],
          "token" => key,
          "userId" => record["userId"],
          "userAgent" => ctx.headers["user-agent"],
          "ipAddress" => ctx.headers["x-forwarded-for"],
          "createdAt" => Time.now,
          "updatedAt" => Time.now,
          "expiresAt" => record["expiresAt"] || (Time.now + ctx.context.options.session[:expires_in].to_i)
        }
      }
      ctx.context.set_current_session(session)
      nil
    end

    def api_key_validate!(ctx, key, config, permissions: nil)
      hashed = api_key_hash(key, config)
      record = api_key_find_by_hash(ctx, hashed, config)
      raise APIError.new("FORBIDDEN", message: API_KEY_ERROR_CODES["INVALID_API_KEY"]) unless record
      raise APIError.new("FORBIDDEN", message: API_KEY_ERROR_CODES["KEY_DISABLED"]) if record["enabled"] == false
      if record["expiresAt"] && record["expiresAt"] <= Time.now
        api_key_delete_record(ctx, record, config)
        raise APIError.new("FORBIDDEN", message: API_KEY_ERROR_CODES["KEY_EXPIRED"])
      end
      if record["remaining"].to_i <= 0 && !record["remaining"].nil? && record["refillAmount"].nil?
        api_key_delete_record(ctx, record, config)
        raise APIError.new("FORBIDDEN", message: API_KEY_ERROR_CODES["USAGE_EXCEEDED"])
      end

      api_key_check_permissions!(record, permissions)
      update = api_key_usage_update(record, config)
      updated = api_key_update_record(ctx, record, update, config, defer: true)
      api_key_migrate_legacy_metadata(ctx, updated || record.merge(update.transform_keys { |key_name| Schema.storage_key(key_name) }), config)
    end

    def api_key_usage_update(record, config)
      now = Time.now
      update = {lastRequest: now, updatedAt: now}

      if api_key_rate_limited?(record, config, now)
        raise APIError.new("TOO_MANY_REQUESTS", message: API_KEY_ERROR_CODES["RATE_LIMIT_EXCEEDED"])
      end
      update[:requestCount] = api_key_next_request_count(record, now)

      remaining = record["remaining"]
      if !remaining.nil?
        if remaining.to_i <= 0 && record["refillAmount"] && record["refillInterval"]
          last_refill = api_key_normalize_time(record["lastRefillAt"] || record["lastRequest"] || record["createdAt"])
          if !last_refill || ((now - last_refill) * 1000) >= record["refillInterval"].to_i
            remaining = record["refillAmount"].to_i
            update[:lastRefillAt] = now
          end
        end
        raise APIError.new("FORBIDDEN", message: API_KEY_ERROR_CODES["USAGE_EXCEEDED"]) if remaining.to_i <= 0

        update[:remaining] = remaining.to_i - 1
      end
      update
    end

    def api_key_rate_limited?(record, config, now)
      return false if config[:rate_limit][:enabled] == false || record["rateLimitEnabled"] == false

      window = record["rateLimitTimeWindow"]
      max = record["rateLimitMax"]
      return false if window.nil? || max.nil?

      last = api_key_normalize_time(record["lastRequest"])
      return false unless last && ((now - last) * 1000) <= window.to_i

      record["requestCount"].to_i >= max.to_i
    end

    def api_key_next_request_count(record, now)
      last = api_key_normalize_time(record["lastRequest"])
      window = record["rateLimitTimeWindow"].to_i
      if last && window.positive? && ((now - last) * 1000) <= window
        record["requestCount"].to_i + 1
      else
        1
      end
    end

    def api_key_validate_create_update!(body, config, create:, client:)
      name = body[:name]
      if create && config[:require_name] && name.to_s.empty?
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["NAME_REQUIRED"])
      end
      if name && !name.to_s.length.between?(config[:minimum_name_length].to_i, config[:maximum_name_length].to_i)
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["INVALID_NAME_LENGTH"])
      end
      prefix = body[:prefix]
      if prefix && !prefix.to_s.length.between?(config[:minimum_prefix_length].to_i, config[:maximum_prefix_length].to_i)
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["INVALID_PREFIX_LENGTH"])
      end
      if body.key?(:metadata)
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["METADATA_DISABLED"]) unless config[:enable_metadata]
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["INVALID_METADATA_TYPE"]) unless body[:metadata].nil? || body[:metadata].is_a?(Hash)
      end
      server_only_keys = %i[refill_amount refill_interval rate_limit_max rate_limit_time_window rate_limit_enabled remaining]
      server_only_keys << :permissions unless create
      if client && server_only_keys.any? { |key| body.key?(key) }
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"])
      end
      if body[:refill_amount] && !body[:refill_interval]
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["REFILL_INTERVAL_AND_AMOUNT_REQUIRED"])
      end
      if body[:refill_interval] && !body[:refill_amount]
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["REFILL_AMOUNT_AND_INTERVAL_REQUIRED"])
      end
      if body.key?(:expires_in)
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["KEY_DISABLED_EXPIRATION"]) if config[:key_expiration][:disable_custom_expires_time]

        days = body[:expires_in].to_f / 86_400
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_SMALL"]) if days < config[:key_expiration][:min_expires_in].to_f
        raise APIError.new("BAD_REQUEST", message: API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_LARGE"]) if days > config[:key_expiration][:max_expires_in].to_f
      end
    end

    def api_key_update_payload(body, _config)
      update = {}
      update[:name] = body[:name] if body.key?(:name)
      update[:enabled] = body[:enabled] unless body[:enabled].nil?
      update[:remaining] = body[:remaining] if body.key?(:remaining)
      update[:refillAmount] = body[:refill_amount] if body.key?(:refill_amount)
      update[:refillInterval] = body[:refill_interval] if body.key?(:refill_interval)
      update[:rateLimitEnabled] = body[:rate_limit_enabled] if body.key?(:rate_limit_enabled)
      update[:rateLimitTimeWindow] = body[:rate_limit_time_window] if body.key?(:rate_limit_time_window)
      update[:rateLimitMax] = body[:rate_limit_max] if body.key?(:rate_limit_max)
      update[:expiresAt] = Time.now + body[:expires_in].to_i if body.key?(:expires_in)
      update[:metadata] = api_key_encode_json(body[:metadata]) if body.key?(:metadata)
      update[:permissions] = api_key_encode_json(body[:permissions]) if body.key?(:permissions)
      update
    end

    def api_key_generate_key(config, prefix)
      generator = config[:custom_key_generator]
      return generator.call({length: config[:default_key_length], prefix: prefix}) if generator.respond_to?(:call)

      "#{prefix}#{Array.new(config[:default_key_length].to_i) { ("A".."Z").to_a[SecureRandom.random_number(26)] }.join}"
    end

    def api_key_hash(key, config)
      config[:disable_key_hashing] ? key.to_s : Crypto.sha256(key.to_s, encoding: :base64url)
    end

    def api_key_expires_at(body, config)
      if body.key?(:expires_in)
        Time.now + body[:expires_in].to_i
      elsif config[:key_expiration][:default_expires_in]
        Time.now + config[:key_expiration][:default_expires_in].to_i
      end
    end

    def api_key_store(ctx, data, config)
      record = nil
      if config[:storage] == "database" || config[:fallback_to_database]
        record = ctx.context.adapter.create(model: API_KEY_TABLE_NAME, data: data)
      end
      record ||= data.transform_keys { |key| Schema.storage_key(key) }.merge("id" => SecureRandom.hex(16))
      api_key_storage_set(ctx, record, config) if config[:storage] == "secondary-storage"
      record
    end

    def api_key_find_by_hash(ctx, hashed, config)
      if config[:storage] == "secondary-storage"
        record = api_key_storage_get(ctx, "api-key:key:#{hashed}", config)
        return record if record
        return nil unless config[:fallback_to_database]
      end
      ctx.context.adapter.find_one(model: API_KEY_TABLE_NAME, where: [{field: "key", value: hashed}])
    end

    def api_key_find_by_id(ctx, id, config)
      if config[:storage] == "secondary-storage"
        record = api_key_storage_get(ctx, "api-key:id:#{id}", config)
        return record if record
        return nil unless config[:fallback_to_database]
      end
      ctx.context.adapter.find_one(model: API_KEY_TABLE_NAME, where: [{field: "id", value: id}])
    end

    def api_key_list_for_user(ctx, user_id, config)
      if config[:storage] == "secondary-storage"
        begin
          ids = JSON.parse(api_key_storage(config, ctx.context)&.get("api-key:user:#{user_id}").to_s)
          records = ids.filter_map { |id| api_key_find_by_id(ctx, id, config) }
          return records unless records.empty? && config[:fallback_to_database]
        rescue JSON::ParserError, NoMethodError
          return [] unless config[:fallback_to_database]
        end
      end
      ctx.context.adapter.find_many(model: API_KEY_TABLE_NAME, where: [{field: "userId", value: user_id}])
    end

    def api_key_update_record(ctx, record, update, config, defer: false)
      performer = lambda do
        updated = nil
        if config[:storage] == "database" || config[:fallback_to_database]
          updated = ctx.context.adapter.update(model: API_KEY_TABLE_NAME, where: [{field: "id", value: record["id"]}], update: update)
        end
        updated ||= record.merge(update.transform_keys { |key| Schema.storage_key(key) })
        api_key_storage_set(ctx, updated, config) if config[:storage] == "secondary-storage"
        updated
      end

      if defer && config[:defer_updates] && api_key_background_tasks?(ctx)
        scheduled = record.merge(update.transform_keys { |key| Schema.storage_key(key) })
        ctx.context.run_in_background(performer)
        scheduled
      else
        performer.call
      end
    end

    def api_key_delete_record(ctx, record, config)
      ctx.context.adapter.delete(model: API_KEY_TABLE_NAME, where: [{field: "id", value: record["id"]}]) if config[:storage] == "database" || config[:fallback_to_database]
      api_key_storage_delete(ctx, record, config) if config[:storage] == "secondary-storage"
    end

    def api_key_delete_expired(context, config)
      return unless config[:storage] == "database" || config[:fallback_to_database]

      expired = context.adapter.find_many(model: API_KEY_TABLE_NAME).select do |record|
        record["expiresAt"] && record["expiresAt"] < Time.now
      end
      expired.each do |record|
        context.adapter.delete(model: API_KEY_TABLE_NAME, where: [{field: "id", value: record["id"]}])
      end
    end

    def api_key_storage(config, context = nil)
      config[:custom_storage] || context&.options&.secondary_storage
    end

    def api_key_storage_get(ctx, key, config)
      raw = api_key_storage(config, ctx.context)&.get(key)
      raw && api_key_deserialize_storage_record(JSON.parse(raw))
    rescue JSON::ParserError
      nil
    end

    def api_key_storage_set(ctx, record, config)
      storage = api_key_storage(config, ctx.context)
      return unless storage

      serialized = JSON.generate(api_key_storage_record(record))
      ttl = record["expiresAt"] ? [(record["expiresAt"] - Time.now).to_i, 0].max : nil
      storage.set("api-key:key:#{record["key"]}", serialized, ttl)
      storage.set("api-key:id:#{record["id"]}", serialized, ttl)
      user_key = "api-key:user:#{record["userId"]}"
      ids = JSON.parse(storage.get(user_key).to_s)
      ids << record["id"] unless ids.include?(record["id"])
      storage.set(user_key, JSON.generate(ids))
    rescue JSON::ParserError
      storage.set("api-key:user:#{record["userId"]}", JSON.generate([record["id"]]))
    end

    def api_key_storage_delete(ctx, record, config)
      storage = api_key_storage(config, ctx.context)
      return unless storage

      storage.delete("api-key:key:#{record["key"]}")
      storage.delete("api-key:id:#{record["id"]}")
      user_key = "api-key:user:#{record["userId"]}"
      ids = JSON.parse(storage.get(user_key).to_s).reject { |id| id == record["id"] }
      ids.empty? ? storage.delete(user_key) : storage.set(user_key, JSON.generate(ids))
    rescue JSON::ParserError
      nil
    end

    def api_key_storage_record(record)
      record.transform_values { |value| value.is_a?(Time) ? value.iso8601 : value }
    end

    def api_key_deserialize_storage_record(record)
      %w[createdAt updatedAt expiresAt lastRefillAt lastRequest].each do |field|
        record[field] = api_key_normalize_time(record[field]) if record[field]
      end
      record
    end

    def api_key_public(record, reveal_key: nil, include_key_field: false)
      data = record.transform_keys(&:to_sym)
      output = data.except(:key)
      output[:key] = reveal_key if include_key_field && reveal_key
      output[:metadata] = api_key_decode_json(data[:metadata])
      output[:permissions] = api_key_decode_json(data[:permissions])
      output
    end

    def api_key_migrate_legacy_metadata(ctx, record, config)
      parsed = api_key_decode_json(record["metadata"])
      return record unless parsed.is_a?(Hash)

      encoded = api_key_encode_json(parsed)
      return record.merge("metadata" => encoded) if record["metadata"] == encoded

      updated = record.merge("metadata" => encoded)
      if config[:storage] == "database" || config[:fallback_to_database]
        ctx.context.adapter.update(model: API_KEY_TABLE_NAME, where: [{field: "id", value: record["id"]}], update: {metadata: encoded})
      end
      api_key_storage_set(ctx, updated, config) if config[:storage] == "secondary-storage"
      updated
    end

    def api_key_background_tasks?(ctx)
      ctx.context.options.advanced.dig(:background_tasks, :handler).respond_to?(:call)
    end

    def api_key_get_from_headers(ctx, config)
      getter = config[:custom_api_key_getter]
      return getter.call(ctx) if getter.respond_to?(:call)

      Array(config[:api_key_headers]).each do |header|
        value = ctx.headers[header.to_s.downcase]
        return value if value
      end
      nil
    end

    def api_key_check_permissions!(record, required)
      return if required.nil? || required == {}

      actual = api_key_decode_json(record["permissions"]) || {}
      required.each do |resource, actions|
        allowed = Array(actual[resource.to_s] || actual[resource.to_sym])
        unless Array(actions).all? { |action| allowed.include?(action) || allowed.include?(action.to_s) }
          raise APIError.new("FORBIDDEN", message: API_KEY_ERROR_CODES["INVALID_API_KEY"])
        end
      end
    end

    def api_key_encode_json(value)
      return nil if value.nil?

      JSON.generate(value)
    end

    def api_key_decode_json(value)
      return nil if value.nil?
      return value if value.is_a?(Hash)

      parsed = JSON.parse(value.to_s)
      parsed.is_a?(String) ? api_key_decode_json(parsed) : parsed
    rescue JSON::ParserError
      nil
    end

    def api_key_normalize_time(value)
      return value if value.is_a?(Time)
      return nil if value.nil?

      Time.parse(value.to_s)
    end
  end
end
