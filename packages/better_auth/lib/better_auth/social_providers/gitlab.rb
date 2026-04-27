# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def gitlab(client_id:, client_secret:, issuer: "https://gitlab.com", scopes: ["read_user"], **options)
      base = issuer.to_s.sub(%r{/+\z}, "")
      {
        id: "gitlab",
        name: "GitLab",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: lambda do |data|
          Base.authorization_url(options[:authorization_endpoint] || "#{base}/oauth/authorize", {
            client_id: client_id,
            redirect_uri: data[:redirect_uri] || data[:redirectURI],
            response_type: "code",
            scope: data[:scopes] || scopes,
            state: data[:state],
            code_challenge: (data[:code_verifier] || data[:codeVerifier]) && Base.pkce_challenge(data[:code_verifier] || data[:codeVerifier]),
            code_challenge_method: (data[:code_verifier] || data[:codeVerifier]) && "S256",
            login_hint: data[:loginHint] || data[:login_hint]
          })
        end,
        validate_authorization_code: lambda do |data|
          Base.post_form("#{base}/oauth/token", {
            client_id: client_id,
            client_secret: client_secret,
            code: data[:code],
            code_verifier: data[:code_verifier] || data[:codeVerifier],
            grant_type: "authorization_code",
            redirect_uri: data[:redirect_uri] || data[:redirectURI]
          })
        end,
        get_user_info: lambda do |tokens|
          profile = Base.get_json("#{base}/api/v4/user", "Authorization" => "Bearer #{Base.access_token(tokens)}")
          return nil if profile["state"] && profile["state"] != "active"

          {
            user: {
              id: profile["id"].to_s,
              email: profile["email"],
              name: profile["name"] || profile["username"],
              image: profile["avatar_url"],
              emailVerified: !!profile["email_verified"]
            },
            data: profile
          }
        end
      }
    end
  end
end
