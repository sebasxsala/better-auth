# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def discord(client_id:, client_secret:, scopes: ["identify", "email"], **options)
      {
        id: "discord",
        name: "Discord",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: lambda do |data|
          selected_scopes = data[:scopes] || scopes
          params = {
            client_id: client_id,
            redirect_uri: data[:redirect_uri] || data[:redirectURI],
            response_type: "code",
            scope: selected_scopes,
            state: data[:state],
            prompt: options.fetch(:prompt, "none")
          }
          params[:permissions] = options[:permissions] if selected_scopes.include?("bot") && options.key?(:permissions)
          Base.authorization_url("https://discord.com/api/oauth2/authorize", params)
        end,
        validate_authorization_code: lambda do |data|
          Base.post_form("https://discord.com/api/oauth2/token", {
            client_id: client_id,
            client_secret: client_secret,
            code: data[:code],
            grant_type: "authorization_code",
            redirect_uri: data[:redirect_uri] || data[:redirectURI]
          })
        end,
        get_user_info: lambda do |tokens|
          profile = Base.get_json("https://discord.com/api/users/@me", "Authorization" => "Bearer #{Base.access_token(tokens)}")
          {
            user: {
              id: profile["id"],
              email: profile["email"],
              name: profile["global_name"] || profile["username"] || "",
              image: discord_avatar_url(profile),
              emailVerified: !!profile["verified"]
            },
            data: profile
          }
        end
      }
    end

    def discord_avatar_url(profile)
      avatar = profile["avatar"]
      return nil unless avatar

      format = avatar.start_with?("a_") ? "gif" : "png"
      "https://cdn.discordapp.com/avatars/#{profile["id"]}/#{avatar}.#{format}"
    end
  end
end
