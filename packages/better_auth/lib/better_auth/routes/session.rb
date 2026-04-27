# frozen_string_literal: true

module BetterAuth
  module Routes
    def self.get_session
      Endpoint.new(path: "/get-session", method: "GET") do |ctx|
        session = current_session(ctx, allow_nil: true)
        next ctx.json(nil) unless session

        ctx.json(parsed_session_response(ctx, session))
      rescue APIError
        raise
      rescue => error
        log(ctx.context, :error, "FAILED_TO_GET_SESSION #{error.message}")
        raise APIError.new("INTERNAL_SERVER_ERROR", message: BASE_ERROR_CODES["FAILED_TO_GET_SESSION"])
      end
    end

    def self.list_sessions
      Endpoint.new(path: "/list-sessions", method: "GET") do |ctx|
        session = current_session(ctx)
        sessions = ctx.context.internal_adapter.list_sessions(session[:user]["id"])
        active = sessions
          .map { |entry| stringify_keys(entry) }
          .select { |entry| !Session.expired?(entry) }
          .map { |entry| Schema.parse_output(ctx.context.options, "session", entry) }
        ctx.json(active)
      end
    end

    def self.revoke_session
      Endpoint.new(path: "/revoke-session", method: "POST") do |ctx|
        session = current_session(ctx, sensitive: true)
        body = normalize_hash(ctx.body)
        token = body["token"].to_s
        found = ctx.context.internal_adapter.find_session(token)

        if found && stringify_keys(found[:session] || found["session"])["userId"] == session[:user]["id"]
          ctx.context.internal_adapter.delete_session(token)
        end

        ctx.json({status: true})
      end
    end

    def self.revoke_sessions
      Endpoint.new(path: "/revoke-sessions", method: "POST") do |ctx|
        session = current_session(ctx, sensitive: true)
        ctx.context.internal_adapter.delete_sessions(session[:user]["id"])
        Cookies.delete_session_cookie(ctx)
        ctx.json({status: true})
      end
    end

    def self.revoke_other_sessions
      Endpoint.new(path: "/revoke-other-sessions", method: "POST") do |ctx|
        session = current_session(ctx, sensitive: true)
        current_token = session[:session]["token"]
        sessions = ctx.context.internal_adapter.list_sessions(session[:user]["id"])
        sessions.each do |entry|
          data = stringify_keys(entry)
          next if Session.expired?(data) || data["token"] == current_token

          ctx.context.internal_adapter.delete_session(data["token"])
        end
        ctx.json({status: true})
      end
    end

    def self.current_session(ctx, allow_nil: false, sensitive: false)
      data = Session.find_current(
        ctx,
        disable_cookie_cache: truthy_query?(ctx.query, "disableCookieCache"),
        disable_refresh: truthy_query?(ctx.query, "disableRefresh"),
        sensitive: sensitive
      )
      return nil if allow_nil && data.nil?

      raise APIError.new("UNAUTHORIZED") unless data

      {
        session: stringify_keys(data[:session] || data["session"]),
        user: stringify_keys(data[:user] || data["user"])
      }
    end

    def self.parsed_session_response(ctx, session)
      {
        session: Schema.parse_output(ctx.context.options, "session", session[:session]),
        user: Schema.parse_output(ctx.context.options, "user", session[:user])
      }
    end

    def self.truthy_query?(query, key)
      snake_key = key.to_s
        .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
        .tr("-", "_")
        .downcase
      value = query[key] ||
        query[key.to_sym] ||
        query[Schema.storage_key(key)] ||
        query[Schema.storage_key(key).to_sym] ||
        query[snake_key] ||
        query[snake_key.to_sym]
      value == true || value.to_s == "true"
    end

    def self.stringify_keys(value)
      return value.each_with_object({}) { |(key, object_value), result| result[key.to_s] = stringify_keys(object_value) } if value.is_a?(Hash)
      return value.map { |entry| stringify_keys(entry) } if value.is_a?(Array)

      value
    end

    def self.log(context, level, message)
      logger = context.logger
      if logger.respond_to?(:call)
        logger.call(level, message)
      elsif logger.respond_to?(level)
        logger.public_send(level, message)
      end
    end
  end
end
