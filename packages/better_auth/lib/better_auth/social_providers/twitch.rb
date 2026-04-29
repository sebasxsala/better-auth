# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def twitch(client_id:, client_secret:, scopes: ["user:read:email", "openid"], **options)
      Base.oauth_provider(
        id: "twitch",
        name: "Twitch",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "https://id.twitch.tv/oauth2/authorize",
        token_endpoint: "https://id.twitch.tv/oauth2/token",
        scopes: scopes,
        auth_params: {
          claims: JSON.generate({
            userinfo: {
              email: nil,
              email_verified: nil,
              preferred_username: nil,
              picture: nil
            }
          })
        },
        profile_map: ->(profile) {
          {
            id: profile["sub"],
            name: profile["preferred_username"],
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
