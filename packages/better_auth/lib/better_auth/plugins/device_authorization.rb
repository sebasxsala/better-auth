# frozen_string_literal: true

require "uri"

module BetterAuth
  module Plugins
    module_function

    DEVICE_AUTHORIZATION_ERROR_CODES = {
      "INVALID_DEVICE_CODE" => "invalid_grant",
      "AUTHORIZATION_PENDING" => "authorization_pending",
      "SLOW_DOWN" => "slow_down",
      "EXPIRED_TOKEN" => "expired_token",
      "ACCESS_DENIED" => "access_denied"
    }.freeze

    def device_authorization(options = {})
      config = {
        expires_in: "30m",
        interval: "5s",
        device_code_length: 40,
        user_code_length: 8
      }.merge(normalize_hash(options))

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
          raise APIError.new("UNAUTHORIZED", message: "invalid_client")
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
        })
      end
    end

    def device_token_endpoint(config)
      Endpoint.new(path: "/device/token", method: "POST", metadata: {allowed_media_types: ["application/x-www-form-urlencoded", "application/json"]}) do |ctx|
        body = OAuthProtocol.stringify_keys(ctx.body)
        raise APIError.new("BAD_REQUEST", message: "unsupported_grant_type") unless body["grant_type"] == OAuthProtocol::DEVICE_CODE_GRANT
        if config[:validate_client] && !config[:validate_client].call(body["client_id"])
          raise APIError.new("UNAUTHORIZED", message: "invalid_client")
        end

        record = find_device_code(ctx, body["device_code"])
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless record
        record = OAuthProtocol.stringify_keys(record)
        if record["clientId"] && record["clientId"] != body["client_id"]
          raise APIError.new("BAD_REQUEST", message: "invalid_client")
        end
        if device_authorization_time(record["expiresAt"]) <= Time.now
          ctx.context.adapter.delete(model: "deviceCode", where: [{field: "id", value: record["id"]}])
          raise APIError.new("BAD_REQUEST", message: "expired_token")
        end
        case record["status"]
        when "approved"
          session = ctx.context.internal_adapter.create_session(record["userId"])
          found = ctx.context.internal_adapter.find_session(session["token"])
          ctx.context.adapter.delete(model: "deviceCode", where: [{field: "id", value: record["id"]}])
          ctx.json({
            access_token: session["token"],
            token_type: "Bearer",
            expires_in: ctx.context.session_config[:expires_in],
            scope: record["scope"].to_s,
            user: found[:user]
          })
        when "denied"
          ctx.context.adapter.delete(model: "deviceCode", where: [{field: "id", value: record["id"]}])
          raise APIError.new("BAD_REQUEST", message: "access_denied")
        else
          if record["lastPolledAt"] && record["pollingInterval"].to_i.positive?
            elapsed = ((Time.now - device_authorization_time(record["lastPolledAt"])) * 1000).to_i
            raise APIError.new("BAD_REQUEST", message: "slow_down") if elapsed < record["pollingInterval"].to_i
          end
          ctx.context.adapter.update(model: "deviceCode", where: [{field: "id", value: record["id"]}], update: {"lastPolledAt" => Time.now})
          raise APIError.new("BAD_REQUEST", message: "authorization_pending")
        end
      end
    end

    def device_verify_endpoint
      Endpoint.new(path: "/device", method: "GET") do |ctx|
        code = normalize_user_code(OAuthProtocol.stringify_keys(ctx.query)["user_code"])
        record = find_device_user_code(ctx, code)
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless record
        record = OAuthProtocol.stringify_keys(record)
        raise APIError.new("BAD_REQUEST", message: "expired_token") if device_authorization_time(record["expiresAt"]) <= Time.now

        ctx.json({status: record["status"], client_id: record["clientId"], scope: record["scope"]})
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
      code = normalize_user_code(OAuthProtocol.stringify_keys(ctx.body)["user_code"])
      record = find_device_user_code(ctx, code)
      raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless record
      record = OAuthProtocol.stringify_keys(record)
      raise APIError.new("BAD_REQUEST", message: "expired_token") if device_authorization_time(record["expiresAt"]) <= Time.now
      raise APIError.new("BAD_REQUEST", message: "device_code_already_processed") unless record["status"] == "pending"

      ctx.context.adapter.update(
        model: "deviceCode",
        where: [{field: "id", value: record["id"]}],
        update: {"status" => status, "userId" => record["userId"] || session[:user]["id"]}
      )
      ctx.json({status: true})
    end

    def find_device_code(ctx, code)
      ctx.context.adapter.find_one(model: "deviceCode", where: [{field: "deviceCode", value: code.to_s}])
    end

    def find_device_user_code(ctx, code)
      ctx.context.adapter.find_one(model: "deviceCode", where: [{field: "userCode", value: code.to_s}])
    end

    def normalize_user_code(value)
      value.to_s.upcase.delete("-").then do |code|
        (code.length == 8) ? "#{code[0, 4]}-#{code[4, 4]}" : value.to_s.upcase
      end
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

      match = value.to_s.match(/\A(\d+)(ms|s|m|h|d)?\z/)
      raise Error, "Invalid time string" unless match

      amount = match[1].to_i
      case match[2]
      when "ms" then (amount / 1000.0).ceil
      when "m" then amount * 60
      when "h" then amount * 3600
      when "d" then amount * 86_400
      else amount
      end
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
