# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def github(client_id:, client_secret:, scopes: ["read:user", "user:email"], **options)
      {
        id: "github",
        name: "GitHub",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: lambda do |data|
          Base.authorization_url(options[:authorization_endpoint] || "https://github.com/login/oauth/authorize", {
            client_id: client_id,
            redirect_uri: data[:redirect_uri] || data[:redirectURI],
            scope: data[:scopes] || scopes,
            state: data[:state],
            login_hint: data[:loginHint] || data[:login_hint],
            prompt: options[:prompt]
          })
        end,
        validate_authorization_code: lambda do |data|
          Base.post_form("https://github.com/login/oauth/access_token", {
            client_id: client_id,
            client_secret: client_secret,
            code: data[:code],
            code_verifier: data[:code_verifier] || data[:codeVerifier],
            redirect_uri: data[:redirect_uri] || data[:redirectURI]
          })
        end,
        get_user_info: lambda do |tokens|
          headers = {
            "Authorization" => "Bearer #{Base.access_token(tokens)}",
            "Accept" => "application/json",
            "User-Agent" => "better-auth"
          }
          profile = Base.get_json("https://api.github.com/user", headers)
          emails = Base.get_json("https://api.github.com/user/emails", headers)
          primary = Array(emails).find { |email| email["email"] == profile["email"] } ||
            Array(emails).find { |email| email["primary"] } ||
            Array(emails).first ||
            {}

          {
            user: {
              id: profile["id"].to_s,
              email: profile["email"] || primary["email"],
              name: profile["name"] || profile["login"],
              image: profile["avatar_url"],
              emailVerified: !!primary["verified"]
            },
            data: profile
          }
        end
      }
    end
  end
end
