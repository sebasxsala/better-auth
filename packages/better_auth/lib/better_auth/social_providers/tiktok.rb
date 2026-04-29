# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def tiktok(client_id:, client_secret:, scopes: ["user.info.profile"], **options)
      client_key = options[:client_key] || options[:clientKey] || client_id
      Base.oauth_provider(
        id: "tiktok",
        name: "TikTok",
        client_id: client_key,
        client_secret: client_secret,
        authorization_endpoint: "https://www.tiktok.com/v2/auth/authorize",
        token_endpoint: "https://open.tiktokapis.com/v2/oauth/token/",
        user_info_endpoint: "https://open.tiktokapis.com/v2/user/info/?fields=open_id,avatar_large_url,display_name,username",
        scopes: scopes,
        scope_separator: ",",
        auth_params: {client_key: client_key},
        token_params: {client_key: client_key},
        profile_map: ->(profile) {
          user = profile.dig("data", "user") || profile
          {
            id: user["open_id"],
            name: user["display_name"] || user["username"] || "",
            email: user["email"] || user["username"],
            image: user["avatar_large_url"],
            emailVerified: false
          }
        },
        **options
      )
    end
  end
end
