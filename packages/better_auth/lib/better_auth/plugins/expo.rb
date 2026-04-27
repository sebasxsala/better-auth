# frozen_string_literal: true

require "rack/utils"
require "uri"

module BetterAuth
  module Plugins
    module_function

    def expo(options = {})
      config = normalize_hash(options)
      Plugin.new(
        id: "expo",
        init: ->(_ctx) { {options: {trusted_origins: ["exp://"]}} },
        on_request: expo_on_request(config),
        hooks: {
          after: [
            {
              matcher: ->(ctx) { %w[/callback /oauth2/callback /magic-link/verify /verify-email].any? { |path| ctx.path.to_s.start_with?(path) } },
              handler: ->(ctx) { expo_inject_cookie_into_deep_link(ctx) }
            }
          ]
        },
        endpoints: {
          expo_authorization_proxy: expo_authorization_proxy_endpoint
        },
        options: config
      )
    end

    def expo_authorization_proxy_endpoint
      Endpoint.new(path: "/expo-authorization-proxy", method: "GET") do |ctx|
        authorization_url = ctx.query[:authorizationURL] || ctx.query["authorizationURL"] || ctx.query[:authorization_url] || ctx.query["authorization_url"]
        oauth_state = ctx.query[:oauthState] || ctx.query["oauthState"] || ctx.query[:oauth_state] || ctx.query["oauth_state"]
        raise APIError.new("BAD_REQUEST", message: "Unexpected error") if authorization_url.to_s.empty?

        if oauth_state
          cookie = ctx.context.create_auth_cookie("oauth_state", max_age: 600)
          ctx.set_cookie(cookie.name, oauth_state, cookie.attributes)
        else
          state = URI.parse(authorization_url).then { |uri| Rack::Utils.parse_query(uri.query)["state"] }
          raise APIError.new("BAD_REQUEST", message: "Unexpected error") if state.to_s.empty?

          cookie = ctx.context.create_auth_cookie("state", max_age: 300)
          ctx.set_signed_cookie(cookie.name, state, ctx.context.secret, cookie.attributes)
        end
        [302, ctx.response_headers.merge("location" => authorization_url), [""]]
      rescue URI::InvalidURIError
        raise APIError.new("BAD_REQUEST", message: "Unexpected error")
      end
    end

    def expo_on_request(config)
      lambda do |request, _context|
        next if config[:disable_origin_override] || request.get_header("HTTP_ORIGIN")

        expo_origin = request.get_header("HTTP_EXPO_ORIGIN")
        next unless expo_origin

        env = request.env.dup
        env["HTTP_ORIGIN"] = expo_origin
        {request: Rack::Request.new(env)}
      end
    end

    def expo_inject_cookie_into_deep_link(ctx)
      location = ctx.response_headers["location"]
      cookie = ctx.response_headers["set-cookie"]
      return unless location && cookie
      return if location.include?("/oauth-proxy-callback")

      uri = URI.parse(location)
      return if %w[http https].include?(uri.scheme)
      return unless ctx.context.trusted_origin?(location)

      query = Rack::Utils.parse_query(uri.query)
      query["cookie"] = cookie.split(";").first
      uri.query = URI.encode_www_form(query)
      ctx.set_header("location", uri.to_s)
    rescue URI::InvalidURIError
      nil
    end
  end
end
