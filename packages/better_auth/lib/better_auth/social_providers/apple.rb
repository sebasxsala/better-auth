# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def apple(client_id:, client_secret:, scopes: ["email", "name"], **options)
      {
        id: "apple",
        name: "Apple",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: lambda do |data|
          Base.authorization_url(options[:authorization_endpoint] || "https://appleid.apple.com/auth/authorize", {
            client_id: client_id,
            redirect_uri: data[:redirect_uri] || data[:redirectURI],
            response_type: "code id_token",
            response_mode: options[:response_mode] || options[:responseMode] || "form_post",
            scope: data[:scopes] || scopes,
            state: data[:state]
          })
        end,
        validate_authorization_code: lambda do |data|
          Base.post_form("https://appleid.apple.com/auth/token", {
            client_id: client_id,
            client_secret: client_secret,
            code: data[:code],
            code_verifier: data[:code_verifier] || data[:codeVerifier],
            grant_type: "authorization_code",
            redirect_uri: data[:redirect_uri] || data[:redirectURI]
          })
        end,
        get_user_info: lambda do |tokens|
          profile = Base.decode_jwt_payload(Base.id_token(tokens))
          apple_user = tokens[:user] || tokens["user"] || {}
          name = apple_user.dig(:name, :firstName) || apple_user.dig("name", "firstName")
          last_name = apple_user.dig(:name, :lastName) || apple_user.dig("name", "lastName")
          full_name = [name, last_name].compact.join(" ").strip
          full_name = profile["name"] || " " if full_name.empty?

          {
            user: {
              id: profile["sub"],
              email: profile["email"],
              name: full_name,
              image: profile["picture"],
              emailVerified: profile["email_verified"] == true || profile["email_verified"] == "true"
            },
            data: profile.merge("name" => full_name)
          }
        end
      }
    end
  end
end
