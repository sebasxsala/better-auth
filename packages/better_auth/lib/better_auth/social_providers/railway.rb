# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def railway(client_id:, client_secret:, scopes: ["openid", "email", "profile"], **options)
      Base.oauth_provider(
        id: "railway",
        name: "Railway",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "https://backboard.railway.com/oauth/auth",
        token_endpoint: "https://backboard.railway.com/oauth/token",
        user_info_endpoint: "https://backboard.railway.com/oauth/me",
        scopes: scopes,
        pkce: true,
        profile_map: ->(profile) {
          {
            id: profile["sub"],
            name: profile["name"],
            email: profile["email"],
            image: profile["picture"],
            emailVerified: false
          }
        },
        **options
      )
    end
  end
end
