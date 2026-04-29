# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def vercel(client_id:, client_secret:, scopes: [], **options)
      Base.oauth_provider(
        id: "vercel",
        name: "Vercel",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "https://vercel.com/oauth/authorize",
        token_endpoint: "https://api.vercel.com/login/oauth/token",
        user_info_endpoint: "https://api.vercel.com/login/oauth/userinfo",
        scopes: scopes,
        pkce: true,
        profile_map: ->(profile) {
          {
            id: profile["sub"],
            name: profile["name"] || profile["preferred_username"] || "",
            email: profile["email"],
            image: profile["picture"],
            emailVerified: !!profile["email_verified"]
          }
        },
        **options
      )
    end
  end
end
