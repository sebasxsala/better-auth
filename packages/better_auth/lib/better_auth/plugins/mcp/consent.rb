# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module_function

      def consent(ctx, config)
        current_session = Routes.current_session(ctx)
        body = OAuthProtocol.stringify_keys(ctx.body)
        pending = config[:store][:consents].delete(body["consent_code"].to_s)
        raise APIError.new("BAD_REQUEST", message: "invalid consent_code") unless pending
        raise APIError.new("BAD_REQUEST", message: "expired consent_code") if pending[:expires_at] <= Time.now

        query = pending[:query]
        if body["accept"] == false || body["accept"].to_s == "false"
          return {redirectURI: OAuthProtocol.redirect_uri_with_params(query["redirect_uri"], error: "access_denied", state: query["state"], iss: validate_issuer_url(OAuthProtocol.issuer(ctx)))}
        end

        granted_scopes = OAuthProtocol.parse_scopes(body["scope"] || body["scopes"])
        granted_scopes = pending[:scopes] if granted_scopes.empty?
        unless granted_scopes.all? { |scope| pending[:scopes].include?(scope) }
          raise APIError.new("BAD_REQUEST", message: "invalid_scope")
        end
        pending[:session] = current_session if current_session
        query = query.merge("scope" => OAuthProtocol.scope_string(granted_scopes)).except("prompt")
        {redirectURI: authorization_redirect_uri(ctx, config, query, pending[:session])}
      end
    end
  end
end
