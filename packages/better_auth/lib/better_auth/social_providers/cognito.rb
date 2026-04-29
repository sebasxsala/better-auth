# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def cognito(client_id:, client_secret: nil, scopes: ["openid", "profile", "email"], **options)
      domain = (options[:domain] || options[:issuer] || "https://cognito-idp.#{options[:region] || "us-east-1"}.amazonaws.com").to_s.sub(%r{/+\z}, "")
      Base.oauth_provider(
        id: "cognito",
        name: "Cognito",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "#{domain}/oauth2/authorize",
        token_endpoint: "#{domain}/oauth2/token",
        user_info_endpoint: "#{domain}/oauth2/userinfo",
        scopes: scopes,
        pkce: true,
        profile_map: ->(profile) {
          {
            id: profile["sub"],
            name: profile["name"] || profile["given_name"] || profile["username"] || "",
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
