# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def paybin(client_id:, client_secret:, scopes: ["openid", "email", "profile"], **options)
      issuer = (options[:issuer] || "https://idp.paybin.io").to_s.sub(%r{/+\z}, "")
      Base.oauth_provider(
        id: "paybin",
        name: "Paybin",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "#{issuer}/oauth2/authorize",
        token_endpoint: "#{issuer}/oauth2/token",
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
