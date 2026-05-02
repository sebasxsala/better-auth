# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_find_user_consent(ctx, session, client_id)
      ctx.context.adapter.find_one(
        model: "oauthConsent",
        where: [
          {field: "clientId", value: client_id},
          {field: "userId", value: session[:user]["id"]}
        ]
      )
    end

    def oauth_consent_response(consent)
      data = OAuthProtocol.stringify_keys(consent)
      {
        id: data["id"],
        client_id: data["clientId"],
        user_id: data["userId"],
        scope: OAuthProtocol.scope_string(data["scopes"]),
        scopes: OAuthProtocol.parse_scopes(data["scopes"])
      }.compact
    end
  end
end
