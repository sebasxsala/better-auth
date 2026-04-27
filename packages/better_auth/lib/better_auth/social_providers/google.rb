# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def google(client_id:, client_secret:, scopes: ["openid", "email", "profile"], **options)
      {
        id: "google",
        name: "Google",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: lambda do |data|
          verifier = data[:code_verifier] || data[:codeVerifier]
          Base.authorization_url(options[:authorization_endpoint] || "https://accounts.google.com/o/oauth2/v2/auth", {
            client_id: client_id,
            redirect_uri: data[:redirect_uri] || data[:redirectURI],
            response_type: "code",
            scope: data[:scopes] || scopes,
            state: data[:state],
            code_challenge: verifier && Base.pkce_challenge(verifier),
            code_challenge_method: verifier && "S256",
            login_hint: data[:loginHint] || data[:login_hint],
            prompt: options[:prompt],
            access_type: options[:access_type] || options[:accessType] || "offline",
            display: data[:display] || options[:display],
            hd: options[:hd],
            include_granted_scopes: "true"
          })
        end,
        validate_authorization_code: lambda do |data|
          Base.post_form("https://oauth2.googleapis.com/token", {
            client_id: client_id,
            client_secret: client_secret,
            code: data[:code],
            code_verifier: data[:code_verifier] || data[:codeVerifier],
            grant_type: "authorization_code",
            redirect_uri: data[:redirect_uri] || data[:redirectURI]
          })
        end,
        get_user_info: lambda do |tokens|
          profile = if Base.id_token(tokens)
            Base.decode_jwt_payload(Base.id_token(tokens))
          else
            Base.get_json(
              "https://openidconnect.googleapis.com/v1/userinfo",
              "Authorization" => "Bearer #{Base.access_token(tokens)}"
            )
          end

          {
            user: {
              id: profile["sub"],
              email: profile["email"],
              name: profile["name"],
              image: profile["picture"],
              emailVerified: !!profile["email_verified"]
            },
            data: profile
          }
        end
      }
    end
  end
end
