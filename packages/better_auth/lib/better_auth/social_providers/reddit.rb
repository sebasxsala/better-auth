# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def reddit(client_id:, client_secret:, scopes: ["identity"], **options)
      Base.oauth_provider(
        id: "reddit",
        name: "Reddit",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "https://www.reddit.com/api/v1/authorize",
        token_endpoint: "https://www.reddit.com/api/v1/access_token",
        user_info_endpoint: "https://oauth.reddit.com/api/v1/me",
        user_info_headers: {"User-Agent" => "better-auth"},
        scopes: scopes,
        auth_params: ->(_data, opts) { {duration: opts[:duration]} },
        profile_map: ->(profile) {
          {
            id: profile["id"],
            name: profile["name"],
            email: profile["oauth_client_id"],
            image: profile["icon_img"].to_s.split("?").first,
            emailVerified: !!profile["has_verified_email"]
          }
        },
        **options
      )
    end
  end
end
