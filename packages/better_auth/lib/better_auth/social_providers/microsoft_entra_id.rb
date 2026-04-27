# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def microsoft_entra_id(client_id:, client_secret:, tenant_id: "common", scopes: ["openid", "profile", "email", "User.Read", "offline_access"], **options)
      authority = options[:authority] || "https://login.microsoftonline.com"
      base = "#{authority.to_s.sub(%r{/+\z}, "")}/#{tenant_id}/oauth2/v2.0"
      {
        id: "microsoft-entra-id",
        name: "Microsoft Entra ID",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: lambda do |data|
          verifier = data[:code_verifier] || data[:codeVerifier]
          Base.authorization_url(options[:authorization_endpoint] || "#{base}/authorize", {
            client_id: client_id,
            redirect_uri: data[:redirect_uri] || data[:redirectURI],
            response_type: "code",
            scope: data[:scopes] || scopes,
            state: data[:state],
            code_challenge: verifier && Base.pkce_challenge(verifier),
            code_challenge_method: verifier && "S256",
            login_hint: data[:loginHint] || data[:login_hint],
            prompt: options[:prompt]
          })
        end,
        validate_authorization_code: lambda do |data|
          Base.post_form("#{base}/token", {
            client_id: client_id,
            client_secret: client_secret,
            code: data[:code],
            code_verifier: data[:code_verifier] || data[:codeVerifier],
            grant_type: "authorization_code",
            redirect_uri: data[:redirect_uri] || data[:redirectURI]
          })
        end,
        get_user_info: lambda do |tokens|
          profile = Base.id_token(tokens) ? Base.decode_jwt_payload(Base.id_token(tokens)) : {}
          profile = Base.get_json("https://graph.microsoft.com/v1.0/me", "Authorization" => "Bearer #{Base.access_token(tokens)}") if profile.empty?
          email = profile["email"] || profile["mail"] || profile["userPrincipalName"] || profile["preferred_username"]

          {
            user: {
              id: profile["sub"] || profile["id"] || profile["oid"],
              email: email,
              name: profile["name"] || profile["displayName"],
              image: profile["picture"],
              emailVerified: microsoft_email_verified?(profile, email)
            },
            data: profile
          }
        end
      }
    end

    def microsoft_email_verified?(profile, email)
      return !!profile["email_verified"] if profile.key?("email_verified")

      Array(profile["verified_primary_email"]).include?(email) ||
        Array(profile["verified_secondary_email"]).include?(email)
    end
  end
end
