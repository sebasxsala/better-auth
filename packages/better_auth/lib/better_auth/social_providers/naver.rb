# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def naver(client_id:, client_secret:, scopes: ["profile", "email"], **options)
      Base.oauth_provider(
        id: "naver",
        name: "Naver",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "https://nid.naver.com/oauth2.0/authorize",
        token_endpoint: "https://nid.naver.com/oauth2.0/token",
        user_info_endpoint: "https://openapi.naver.com/v1/nid/me",
        scopes: scopes,
        profile_map: ->(profile) {
          data = profile["response"] || {}
          {
            id: data["id"],
            name: data["name"] || data["nickname"] || "",
            email: data["email"],
            image: data["profile_image"],
            emailVerified: false
          }
        },
        **options
      )
    end
  end
end
