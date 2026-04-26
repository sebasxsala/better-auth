# frozen_string_literal: true

require "openssl"

module BetterAuth
  module Plugins
    module JWT
      module_function

      def public_key(jwk)
        OpenSSL::PKey::RSA.new(jwk[:pem] || jwk["pem"])
      end
    end

    module_function

    def jwt(options = {})
      config = normalize_hash(options)
      validate_jwt_options!(config)
      jwks_path = config.dig(:jwks, :jwks_path) || "/jwks"

      Plugin.new(
        id: "jwt",
        endpoints: {
          get_jwks: get_jwks_endpoint(config, jwks_path),
          get_token: get_token_endpoint(config),
          sign_jwt: sign_jwt_endpoint(config),
          verify_jwt: verify_jwt_endpoint(config)
        },
        hooks: {
          after: [
            {
              matcher: ->(ctx) { ctx.path == "/get-session" },
              handler: ->(ctx) { set_jwt_header(ctx, config) }
            }
          ]
        },
        schema: {
          jwks: {
            fields: {
              publicKey: {type: "string", required: true},
              privateKey: {type: "string", required: true},
              createdAt: {type: "date", required: true},
              expiresAt: {type: "date", required: false},
              alg: {type: "string", required: false},
              pem: {type: "string", required: false},
              n: {type: "string", required: false},
              e: {type: "string", required: false}
            }
          }
        },
        options: config
      )
    end

    def validate_jwt_options!(config)
      if config.dig(:jwt, :sign) && !config.dig(:jwks, :remote_url)
        raise Error, "options.jwks.remoteUrl must be set when using options.jwt.sign"
      end

      if config.dig(:jwks, :remote_url) && !config.dig(:jwks, :key_pair_config, :alg)
        raise Error, "options.jwks.keyPairConfig.alg must be specified when using the oidc plugin with options.jwks.remoteUrl"
      end

      path = config.dig(:jwks, :jwks_path)
      if path && (!path.is_a?(String) || path.empty? || !path.start_with?("/") || path.include?(".."))
        raise Error, "options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '.."
      end
    end

    def get_jwks_endpoint(config, path)
      Endpoint.new(path: path, method: "GET") do |ctx|
        raise APIError.new("NOT_FOUND") if config.dig(:jwks, :remote_url)

        key = latest_jwk(ctx, config) || create_jwk(ctx, config)
        ctx.json({keys: [public_jwk(key, config)]})
      end
    end

    def get_token_endpoint(config)
      Endpoint.new(path: "/token", method: "GET") do |ctx|
        session = Session.find_current(ctx)
        raise APIError.new("UNAUTHORIZED", message: BASE_ERROR_CODES["FAILED_TO_GET_SESSION"]) unless session

        ctx.json({token: jwt_token(ctx, session, config)})
      end
    end

    def sign_jwt_endpoint(config)
      Endpoint.new(path: nil, method: "POST") do |ctx|
        payload = fetch_value(ctx.body, "payload") || {}
        override = normalize_hash(fetch_value(ctx.body, "overrideOptions") || {})
        ctx.json({token: sign_jwt_payload(ctx, stringify_payload(payload), deep_merge(config, override))})
      end
    end

    def verify_jwt_endpoint(config)
      Endpoint.new(path: nil, method: "POST") do |ctx|
        token = fetch_value(ctx.body, "token")
        issuer = fetch_value(ctx.body, "issuer")
        verify_options = issuer ? deep_merge(config, jwt: {issuer: issuer}) : config
        ctx.json({payload: verify_jwt_token(ctx, token, verify_options)})
      end
    end

    def set_jwt_header(ctx, config)
      return if config[:disable_setting_jwt_header]

      session = ctx.context.current_session || ctx.context.new_session
      return unless session && session[:session]

      token = jwt_token(ctx, session, config)
      exposed = ctx.response_headers["access-control-expose-headers"].to_s.split(",").map(&:strip).reject(&:empty?)
      exposed << "set-auth-jwt"
      ctx.set_header("set-auth-jwt", token)
      ctx.set_header("access-control-expose-headers", exposed.uniq.join(", "))
      nil
    end

    def jwt_token(ctx, session, config)
      jwt_config = config[:jwt] || {}
      payload = if jwt_config[:define_payload].respond_to?(:call)
        jwt_config[:define_payload].call(session)
      else
        session[:user]
      end
      subject = if jwt_config[:get_subject].respond_to?(:call)
        jwt_config[:get_subject].call(session)
      else
        session[:user]["id"]
      end
      sign_jwt_payload(ctx, stringify_payload(payload).merge("sub" => subject), config)
    end

    def sign_jwt_payload(ctx, payload, config)
      jwt_config = config[:jwt] || {}
      now = Time.now.to_i
      payload = stringify_payload(payload).dup
      payload["iat"] ||= now
      payload["exp"] ||= jwt_expiration(jwt_config[:expiration_time] || "15m", payload["iat"])
      payload["iss"] ||= jwt_config[:issuer] || ctx.context.base_url
      payload["aud"] ||= jwt_config[:audience] || ctx.context.base_url

      return jwt_config[:sign].call(payload) if jwt_config[:sign].respond_to?(:call)

      key = latest_jwk(ctx, config) || create_jwk(ctx, config)
      private_key = OpenSSL::PKey::RSA.new(key["privateKey"])
      ::JWT.encode(payload, private_key, key["alg"] || "RS256", kid: key["id"])
    end

    def verify_jwt_token(ctx, token, config)
      header = ::JWT.decode(token.to_s, nil, false).last
      key = all_jwks(ctx, config).find { |entry| entry["id"] == header["kid"] }
      return nil unless key

      options = {algorithm: key["alg"] || "RS256"}
      if config.dig(:jwt, :issuer)
        options[:iss] = config.dig(:jwt, :issuer)
        options[:verify_iss] = true
      end
      if config.dig(:jwt, :audience)
        options[:aud] = config.dig(:jwt, :audience)
        options[:verify_aud] = true
      end
      decoded, = ::JWT.decode(token.to_s, OpenSSL::PKey::RSA.new(key["publicKey"]), true, options)
      decoded
    rescue ::JWT::DecodeError, OpenSSL::PKey::PKeyError
      nil
    end

    def latest_jwk(ctx, config)
      all_jwks(ctx, config).max_by { |entry| normalize_time(entry["createdAt"]) || Time.at(0) }
    end

    def all_jwks(ctx, config)
      adapter = config[:adapter]
      if adapter && adapter[:get_jwks].respond_to?(:call)
        return Array(adapter[:get_jwks].call(ctx)).map { |entry| stringify_payload(entry) }
      end

      ctx.context.adapter.find_many(model: "jwks")
    end

    def create_jwk(ctx, config)
      adapter = config[:adapter]
      pair = OpenSSL::PKey::RSA.generate(2048)
      public_key = pair.public_key
      data = {
        "id" => Crypto.uuid,
        "publicKey" => public_key.to_pem,
        "privateKey" => pair.to_pem,
        "createdAt" => Time.now,
        "alg" => "RS256",
        "pem" => public_key.to_pem,
        "n" => base64url_bn(public_key.n),
        "e" => base64url_bn(public_key.e)
      }
      data["expiresAt"] = Time.now + config.dig(:jwks, :rotation_interval).to_i if config.dig(:jwks, :rotation_interval)

      if adapter && adapter[:create_jwk].respond_to?(:call)
        return stringify_payload(adapter[:create_jwk].call(data, ctx))
      end

      ctx.context.adapter.create(model: "jwks", data: data, force_allow_id: true)
    end

    def public_jwk(key, _config)
      {
        kid: key["id"],
        kty: "RSA",
        alg: key["alg"] || "RS256",
        use: "sig",
        n: key["n"],
        e: key["e"],
        pem: key["pem"] || key["publicKey"]
      }
    end

    def jwt_expiration(value, iat)
      return value.to_i if value.is_a?(Integer)
      return value.to_i if value.is_a?(Time)

      iat.to_i + parse_duration(value.to_s)
    end

    def parse_duration(value)
      match = value.strip.match(/\A(-?\d+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|week|weeks|y|yr|yrs|year|years)(?:\s+from now|\s+ago)?\z/i)
      raise TypeError, "Invalid time string" unless match

      amount = match[1].to_i
      amount = -amount if value.include?("ago")
      unit = match[2].downcase
      multiplier = case unit
      when "s", "sec", "secs", "second", "seconds" then 1
      when "m", "min", "mins", "minute", "minutes" then 60
      when "h", "hr", "hrs", "hour", "hours" then 3600
      when "d", "day", "days" then 86_400
      when "w", "week", "weeks" then 604_800
      else 31_557_600
      end
      amount * multiplier
    end

    def base64url_bn(number)
      hex = number.to_s(16)
      hex = "0#{hex}" if hex.length.odd?
      Crypto.base64url_encode([hex].pack("H*"))
    end

    def deep_merge(base, override)
      normalize_hash(base || {}).merge(normalize_hash(override || {})) do |_key, old_value, new_value|
        if old_value.is_a?(Hash) && new_value.is_a?(Hash)
          deep_merge(old_value, new_value)
        else
          new_value
        end
      end
    end

    def stringify_payload(value)
      return value.each_with_object({}) { |(key, object_value), result| result[key.to_s] = stringify_payload(object_value) } if value.is_a?(Hash)
      return value.map { |entry| stringify_payload(entry) } if value.is_a?(Array)

      value
    end

    def normalize_time(value)
      return value if value.is_a?(Time)
      return nil if value.nil?

      Time.parse(value.to_s)
    end
  end
end
