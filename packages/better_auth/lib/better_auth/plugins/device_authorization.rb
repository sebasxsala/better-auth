# frozen_string_literal: true

require "uri"

module BetterAuth
  module Plugins
    module_function

    DEVICE_AUTHORIZATION_ERROR_CODES = {
      "INVALID_DEVICE_CODE" => "Invalid device code",
      "EXPIRED_DEVICE_CODE" => "Device code has expired",
      "EXPIRED_USER_CODE" => "User code has expired",
      "AUTHORIZATION_PENDING" => "Authorization pending",
      "ACCESS_DENIED" => "Access denied",
      "INVALID_USER_CODE" => "Invalid user code",
      "DEVICE_CODE_ALREADY_PROCESSED" => "Device code already processed",
      "POLLING_TOO_FREQUENTLY" => "Polling too frequently",
      "USER_NOT_FOUND" => "User not found",
      "FAILED_TO_CREATE_SESSION" => "Failed to create session",
      "INVALID_DEVICE_CODE_STATUS" => "Invalid device code status",
      "AUTHENTICATION_REQUIRED" => "Authentication required"
    }.freeze

    def device_authorization(options = {})
      config = {
        expires_in: "30m",
        interval: "5s",
        device_code_length: 40,
        user_code_length: 8
      }.merge(normalize_hash(options))
      validate_device_authorization_options!(config)

      Plugin.new(
        id: "device-authorization",
        endpoints: {
          device_code: device_code_endpoint(config),
          device_token: device_token_endpoint(config),
          device_verify: device_verify_endpoint,
          device_approve: device_approve_endpoint,
          device_deny: device_deny_endpoint
        },
        schema: device_authorization_schema,
        error_codes: DEVICE_AUTHORIZATION_ERROR_CODES,
        options: config
      )
    end

    def device_code_endpoint(config)
      Endpoint.new(path: "/device/code", method: "POST") do |ctx|
        body = OAuthProtocol.stringify_keys(ctx.body)
        client_id = body["client_id"]
        if config[:validate_client] && !config[:validate_client].call(client_id)
          raise device_authorization_error("BAD_REQUEST", "invalid_client", "Invalid client ID")
        end

        device_code = callable_or_random(config[:generate_device_code], config[:device_code_length])
        user_code = callable_or_random(config[:generate_user_code], config[:user_code_length]).upcase
        expires_in = duration_seconds(config[:expires_in])
        interval = duration_seconds(config[:interval])
        ctx.context.adapter.create(
          model: "deviceCode",
          data: {
            "deviceCode" => device_code,
            "userCode" => user_code,
            "expiresAt" => Time.now + expires_in,
            "status" => "pending",
            "pollingInterval" => interval * 1000,
            "clientId" => client_id,
            "scope" => body["scope"]
          }
        )
        config[:on_device_auth_request].call(client_id, body["scope"]) if config[:on_device_auth_request].respond_to?(:call)

        verification_uri = verification_uri(ctx, config)
        complete = OAuthProtocol.redirect_uri_with_params(verification_uri, user_code: user_code)
        ctx.json({
          device_code: device_code,
          user_code: user_code,
          verification_uri: verification_uri,
          verification_uri_complete: complete,
          expires_in: expires_in,
          interval: interval
        }, headers: {"Cache-Control" => "no-store"})
      end
    end

    def device_token_endpoint(config)
      Endpoint.new(path: "/device/token", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        body = OAuthProtocol.stringify_keys(ctx.body)
        raise device_authorization_error("BAD_REQUEST", "invalid_request", "Unsupported grant type") unless body["grant_type"] == OAuthProtocol::DEVICE_CODE_GRANT
        if config[:validate_client] && !config[:validate_client].call(body["client_id"])
          raise device_authorization_error("BAD_REQUEST", "invalid_grant", "Invalid client ID")
        end

        record = find_device_code(ctx, body["device_code"])
        raise device_authorization_error("BAD_REQUEST", "invalid_grant", DEVICE_AUTHORIZATION_ERROR_CODES["INVALID_DEVICE_CODE"]) unless record
        record = OAuthProtocol.stringify_keys(record)
        if record["clientId"] && record["clientId"] != body["client_id"]
          raise device_authorization_error("BAD_REQUEST", "invalid_grant", "Client ID mismatch")
        end

        if record["lastPolledAt"] && record["pollingInterval"].to_i.positive?
          elapsed = ((Time.now - device_authorization_time(record["lastPolledAt"])) * 1000).to_i
          raise device_authorization_error("BAD_REQUEST", "slow_down", DEVICE_AUTHORIZATION_ERROR_CODES["POLLING_TOO_FREQUENTLY"]) if elapsed < record["pollingInterval"].to_i
        end

        ctx.context.adapter.update(model: "deviceCode", where: [{field: "id", value: record["id"]}], update: {"lastPolledAt" => Time.now})

        if device_authorization_time(record["expiresAt"]) <= Time.now
          ctx.context.adapter.delete(model: "deviceCode", where: [{field: "id", value: record["id"]}])
          raise device_authorization_error("BAD_REQUEST", "expired_token", DEVICE_AUTHORIZATION_ERROR_CODES["EXPIRED_DEVICE_CODE"])
        end

        case record["status"]
        when "pending"
          raise device_authorization_error("BAD_REQUEST", "authorization_pending", DEVICE_AUTHORIZATION_ERROR_CODES["AUTHORIZATION_PENDING"])
        when "denied"
          ctx.context.adapter.delete(model: "deviceCode", where: [{field: "id", value: record["id"]}])
          raise device_authorization_error("BAD_REQUEST", "access_denied", DEVICE_AUTHORIZATION_ERROR_CODES["ACCESS_DENIED"])
        when "approved"
          user = ctx.context.internal_adapter.find_user_by_id(record["userId"])
          raise device_authorization_error("INTERNAL_SERVER_ERROR", "server_error", DEVICE_AUTHORIZATION_ERROR_CODES["USER_NOT_FOUND"]) unless user

          session = ctx.context.internal_adapter.create_session(user["id"])
          raise device_authorization_error("INTERNAL_SERVER_ERROR", "server_error", DEVICE_AUTHORIZATION_ERROR_CODES["FAILED_TO_CREATE_SESSION"]) unless session

          session_data = {session: session, user: user}
          ctx.context.set_new_session(session_data) if ctx.context.respond_to?(:set_new_session)
          ctx.context.adapter.delete(model: "deviceCode", where: [{field: "id", value: record["id"]}])
          ctx.json({
            access_token: session["token"],
            token_type: "Bearer",
            expires_in: [session["expiresAt"].to_i - Time.now.to_i, 0].max,
            scope: record["scope"].to_s
          }, headers: {"Cache-Control" => "no-store", "Pragma" => "no-cache"})
        else
          raise device_authorization_error("INTERNAL_SERVER_ERROR", "server_error", DEVICE_AUTHORIZATION_ERROR_CODES["INVALID_DEVICE_CODE_STATUS"])
        end
      end
    end

    def device_verify_endpoint
      Endpoint.new(path: "/device", method: "GET") do |ctx|
        code = normalize_user_code(OAuthProtocol.stringify_keys(ctx.query)["user_code"])
        record = find_device_user_code(ctx, code)
        raise device_authorization_error("BAD_REQUEST", "invalid_request", DEVICE_AUTHORIZATION_ERROR_CODES["INVALID_USER_CODE"]) unless record
        record = OAuthProtocol.stringify_keys(record)
        raise device_authorization_error("BAD_REQUEST", "expired_token", DEVICE_AUTHORIZATION_ERROR_CODES["EXPIRED_USER_CODE"]) if device_authorization_time(record["expiresAt"]) <= Time.now

        ctx.json({user_code: code, status: record["status"], client_id: record["clientId"], scope: record["scope"]})
      end
    end

    def device_approve_endpoint
      Endpoint.new(path: "/device/approve", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        process_device_decision(ctx, session, "approved")
      end
    end

    def device_deny_endpoint
      Endpoint.new(path: "/device/deny", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        process_device_decision(ctx, session, "denied")
      end
    end

    def process_device_decision(ctx, session, status)
      body = OAuthProtocol.stringify_keys(ctx.body)
      code = normalize_user_code(body["userCode"] || body["user_code"])
      record = find_device_user_code(ctx, code)
      action = (status == "approved") ? "approve" : "deny"
      raise device_authorization_error("BAD_REQUEST", "invalid_request", DEVICE_AUTHORIZATION_ERROR_CODES["INVALID_USER_CODE"]) unless record
      record = OAuthProtocol.stringify_keys(record)
      raise device_authorization_error("BAD_REQUEST", "expired_token", DEVICE_AUTHORIZATION_ERROR_CODES["EXPIRED_USER_CODE"]) if device_authorization_time(record["expiresAt"]) <= Time.now
      raise device_authorization_error("BAD_REQUEST", "invalid_request", DEVICE_AUTHORIZATION_ERROR_CODES["DEVICE_CODE_ALREADY_PROCESSED"]) unless record["status"] == "pending"
      if record["userId"] && record["userId"] != session[:user]["id"]
        raise device_authorization_error("FORBIDDEN", "access_denied", "You are not authorized to #{action} this device authorization")
      end

      ctx.context.adapter.update(
        model: "deviceCode",
        where: [{field: "id", value: record["id"]}],
        update: {"status" => status, "userId" => record["userId"] || session[:user]["id"]}
      )
      ctx.json({success: true})
    end

    def find_device_code(ctx, code)
      ctx.context.adapter.find_one(model: "deviceCode", where: [{field: "deviceCode", value: code.to_s}])
    end

    def find_device_user_code(ctx, code)
      device_authorization_user_code_candidates(code).each do |candidate|
        record = ctx.context.adapter.find_one(model: "deviceCode", where: [{field: "userCode", value: candidate}])
        return record if record
      end
      nil
    end

    def normalize_user_code(value)
      value.to_s.upcase
    end

    def callable_or_random(callable, length)
      callable.respond_to?(:call) ? callable.call.to_s : Crypto.random_string(length.to_i)
    end

    def verification_uri(ctx, config)
      uri = config[:verification_uri] || "/device"
      return uri if uri.to_s.start_with?("http://", "https://")

      "#{OAuthProtocol.endpoint_base(ctx)}#{uri.to_s.start_with?("/") ? uri : "/#{uri}"}"
    end

    def duration_seconds(value)
      return value if value.is_a?(Integer)

      match = value.to_s.match(/\A(\d+)(ms|s|m|min|h|d)?\z/)
      raise Error, "Invalid time string" unless match

      amount = match[1].to_i
      case match[2]
      when "ms" then (amount / 1000.0).ceil
      when "m", "min" then amount * 60
      when "h" then amount * 3600
      when "d" then amount * 86_400
      else amount
      end
    end

    def validate_device_authorization_options!(config)
      duration_seconds(config[:expires_in])
      duration_seconds(config[:interval])
      raise Error, "device_code_length must be a positive integer" unless positive_integer?(config[:device_code_length])
      raise Error, "user_code_length must be a positive integer" unless positive_integer?(config[:user_code_length])
      raise Error, "generate_device_code must be callable" if config.key?(:generate_device_code) && !config[:generate_device_code].respond_to?(:call)
      raise Error, "generate_user_code must be callable" if config.key?(:generate_user_code) && !config[:generate_user_code].respond_to?(:call)
      raise Error, "validate_client must be callable" if config.key?(:validate_client) && !config[:validate_client].respond_to?(:call)
      raise Error, "on_device_auth_request must be callable" if config.key?(:on_device_auth_request) && !config[:on_device_auth_request].respond_to?(:call)
      raise Error, "verification_uri must be a string" if config.key?(:verification_uri) && !config[:verification_uri].is_a?(String)
    end

    def positive_integer?(value)
      value.is_a?(Integer) && value.positive?
    end

    def device_authorization_user_code_candidates(value)
      original = value.to_s.upcase
      clean = original.delete("-")
      dashed = (clean.length == 8) ? "#{clean[0, 4]}-#{clean[4, 4]}" : clean
      [original, clean, dashed].uniq
    end

    def device_authorization_error(status, error, description)
      APIError.new(status, code: error, message: description, body: {error: error, error_description: description})
    end

    def device_authorization_time(value)
      return value if value.is_a?(Time)

      Time.parse(value.to_s)
    end

    def device_authorization_schema
      {
        deviceCode: {
          fields: {
            deviceCode: {type: "string", required: true},
            userCode: {type: "string", required: true},
            userId: {type: "string", required: false},
            expiresAt: {type: "date", required: true},
            status: {type: "string", required: true},
            lastPolledAt: {type: "date", required: false},
            pollingInterval: {type: "number", required: false},
            clientId: {type: "string", required: false},
            scope: {type: "string", required: false}
          }
        }
      }
    end
  end
end
