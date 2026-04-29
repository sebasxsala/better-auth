# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def vk(client_id:, client_secret:, scopes: ["email", "phone"], **options)
      Base.oauth_provider(
        id: "vk",
        name: "VK",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "https://id.vk.com/authorize",
        token_endpoint: "https://id.vk.com/oauth2/auth",
        user_info_endpoint: "https://id.vk.com/oauth2/user_info",
        user_info_method: :post,
        user_info_body: {client_id: client_id},
        scopes: scopes,
        pkce: true,
        profile_map: ->(profile) {
          user = profile["user"] || profile
          {
            id: user["user_id"],
            name: [user["first_name"], user["last_name"]].compact.join(" "),
            email: user["email"],
            image: user["avatar"],
            emailVerified: false
          }
        },
        **options
      )
    end
  end
end
