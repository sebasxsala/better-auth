# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def twitter(client_id:, client_secret:, scopes: ["users.read", "tweet.read", "offline.access", "users.email"], **options)
      Base.oauth_provider(
        id: "twitter",
        name: "Twitter",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "https://x.com/i/oauth2/authorize",
        token_endpoint: "https://api.x.com/2/oauth2/token",
        user_info_endpoint: "https://api.x.com/2/users/me?user.fields=profile_image_url,verified",
        scopes: scopes,
        pkce: true,
        profile_map: ->(profile) {
          data = profile["data"] || profile
          {
            id: data["id"],
            name: data["name"],
            email: data["email"] || data["username"],
            image: data["profile_image_url"],
            emailVerified: !!data["confirmed_email"]
          }
        },
        **options
      )
    end
  end
end
