# frozen_string_literal: true

require "json"
require "uri"

module BetterAuth
  module Plugins
    module_function

    def oauth_proxy(options = {})
      config = {max_age: 60}.merge(normalize_hash(options))

      Plugin.new(
        id: "oauth-proxy",
        endpoints: {
          o_auth_proxy: oauth_proxy_endpoint(config)
        },
        hooks: {
          before: [
            {
              matcher: ->(ctx) { oauth_proxy_sign_in_path?(ctx.path) },
              handler: ->(ctx) { oauth_proxy_before_sign_in(ctx, config) }
            }
          ],
          after: [
            {
              matcher: ->(ctx) { oauth_proxy_callback_path?(ctx.path) },
              handler: ->(ctx) { oauth_proxy_after_callback(ctx, config) }
            }
          ]
        },
        options: config
      )
    end

    def oauth_proxy_endpoint(config)
      Endpoint.new(path: "/oauth-proxy-callback", method: "GET") do |ctx|
        query = normalize_hash(ctx.query)
        decrypted = Crypto.symmetric_decrypt(key: ctx.context.secret, data: query[:cookies].to_s)
        raise ctx.redirect(oauth_proxy_error_url(ctx, "OAuthProxy - Invalid cookies or secret")) unless decrypted

        payload = JSON.parse(decrypted)
        cookies = payload["cookies"]
        timestamp = payload["timestamp"]
        unless cookies.is_a?(String) && timestamp.is_a?(Numeric)
          raise ctx.redirect(oauth_proxy_error_url(ctx, "OAuthProxy - Invalid payload structure"))
        end

        age = ((Time.now.to_f * 1000) - timestamp.to_f) / 1000
        if age > config[:max_age].to_i || age < -10
          raise ctx.redirect(oauth_proxy_error_url(ctx, "OAuthProxy - Payload expired or invalid"))
        end

        oauth_proxy_parse_set_cookie(cookies).each do |cookie|
          ctx.set_cookie(cookie[:name], cookie[:value], cookie[:options])
        end
        raise ctx.redirect(query[:callback_url] || query[:callbackURL] || "/")
      rescue JSON::ParserError
        raise ctx.redirect(oauth_proxy_error_url(ctx, "OAuthProxy - Invalid payload format"))
      end
    end

    def oauth_proxy_before_sign_in(ctx, config)
      return if oauth_proxy_skip?(ctx, config)
      return unless ctx.body.is_a?(Hash)

      original_callback = ctx.body["callbackURL"] || ctx.body["callbackUrl"] || ctx.body["callback_url"] || ctx.body[:callbackURL] || ctx.body[:callback_url] || ctx.context.base_url
      current = oauth_proxy_current_uri(ctx, config)
      callback = "#{oauth_proxy_strip_trailing(current.origin)}#{ctx.context.options.base_path}/oauth-proxy-callback?callbackURL=#{URI.encode_www_form_component(original_callback)}"
      ctx.body = ctx.body.merge("callbackURL" => callback, :callback_url => callback)
      nil
    end

    def oauth_proxy_after_callback(ctx, config)
      location = ctx.response_headers["location"]
      return unless location.to_s.include?("/oauth-proxy-callback?callbackURL")
      return unless location.to_s.start_with?("http")

      location_uri = URI.parse(location)
      production = oauth_proxy_production_uri(ctx, config)
      if location_uri.origin == production.origin
        original = Rack::Utils.parse_query(location_uri.query).fetch("callbackURL", nil)
        oauth_proxy_set_location(ctx, original) if original
        return nil
      end

      set_cookie = ctx.response_headers["set-cookie"]
      return if set_cookie.to_s.empty?

      encrypted = Crypto.symmetric_encrypt(
        key: ctx.context.secret,
        data: JSON.generate({
          cookies: set_cookie,
          timestamp: (Time.now.to_f * 1000).to_i
        })
      )
      separator = location.include?("?") ? "&" : "?"
      oauth_proxy_set_location(ctx, "#{location}#{separator}cookies=#{URI.encode_www_form_component(encrypted)}")
      nil
    rescue URI::InvalidURIError
      nil
    end

    def oauth_proxy_sign_in_path?(path)
      path.to_s.start_with?("/sign-in/social", "/sign-in/oauth2")
    end

    def oauth_proxy_callback_path?(path)
      path.to_s.start_with?("/callback", "/oauth2/callback")
    end

    def oauth_proxy_skip?(ctx, config)
      current = oauth_proxy_current_uri(ctx, config)
      production = oauth_proxy_production_uri(ctx, config)
      current.origin == production.origin
    rescue URI::InvalidURIError
      false
    end

    def oauth_proxy_current_uri(ctx, config)
      URI.parse((config[:current_url] || ctx.context.options.base_url || ctx.context.base_url).to_s)
    end

    def oauth_proxy_production_uri(ctx, config)
      URI.parse((config[:production_url] || ctx.context.options.base_url || ctx.context.base_url).to_s)
    end

    def oauth_proxy_strip_trailing(value)
      value.to_s.sub(%r{/+\z}, "")
    end

    def oauth_proxy_error_url(ctx, message)
      base = ctx.context.options.on_api_error[:error_url] || "#{oauth_proxy_strip_trailing(ctx.context.base_url)}/error"
      uri = URI.parse(base)
      params = URI.decode_www_form(uri.query.to_s)
      params << ["error", message]
      uri.query = URI.encode_www_form(params)
      uri.to_s
    end

    def oauth_proxy_set_location(ctx, location)
      ctx.set_header("location", location)
      return unless ctx.returned.is_a?(APIError)

      headers = ctx.returned.headers.merge("location" => location)
      ctx.returned.instance_variable_set(:@headers, headers)
    end

    def oauth_proxy_parse_set_cookie(header)
      header.to_s.split(/\n|,(?=\s*[^;,]+=)/).filter_map do |line|
        parts = line.strip.split(/;\s*/)
        name, value = parts.shift.to_s.split("=", 2)
        next if name.to_s.empty?

        options = {}
        parts.each do |part|
          key, option_value = part.split("=", 2)
          case key.to_s.downcase
          when "path" then options[:path] = option_value
          when "expires" then options[:expires] = option_value
          when "samesite" then options[:same_site] = option_value
          when "httponly" then options[:http_only] = true
          when "secure" then options[:secure] = true
          when "max-age" then options[:max_age] = option_value
          end
        end
        {name: Cookies.strip_secure_cookie_prefix(name), value: URI.decode_www_form_component(value.to_s), options: options}
      end
    end
  end
end
