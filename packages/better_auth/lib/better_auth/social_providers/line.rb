# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def line(client_id:, client_secret:, scopes: ["openid", "profile", "email"], **options)
      provider = Base.oauth_provider(
        id: "line",
        name: "LINE",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "https://access.line.me/oauth2/v2.1/authorize",
        token_endpoint: "https://api.line.me/oauth2/v2.1/token",
        user_info_endpoint: "https://api.line.me/oauth2/v2.1/userinfo",
        scopes: scopes,
        pkce: true,
        profile_map: ->(profile) {
          {
            id: profile["sub"] || profile["userId"],
            name: profile["name"] || profile["displayName"] || "",
            email: profile["email"],
            image: profile["picture"] || profile["pictureUrl"],
            emailVerified: false
          }
        },
        **options
      )
      provider[:verify_id_token] = provider[:options][:verify_id_token] || ->(token, _nonce = nil) { provider[:options][:disable_id_token_sign_in] ? false : !Base.decode_jwt_payload(token).empty? }
      provider
    end
  end
end
