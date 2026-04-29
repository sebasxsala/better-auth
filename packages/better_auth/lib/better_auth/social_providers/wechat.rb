# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def wechat(client_id:, client_secret:, scopes: ["snsapi_login"], **options)
      provider = Base.oauth_provider(
        id: "wechat",
        name: "WeChat",
        client_id: client_id,
        client_secret: client_secret,
        authorization_endpoint: "https://open.weixin.qq.com/connect/qrconnect",
        token_endpoint: "https://api.weixin.qq.com/sns/oauth2/access_token",
        user_info_endpoint: "https://api.weixin.qq.com/sns/userinfo",
        scopes: scopes,
        scope_separator: ",",
        profile_map: ->(profile) {
          {
            id: profile["unionid"] || profile["openid"],
            name: profile["nickname"],
            email: profile["email"],
            image: profile["headimgurl"],
            emailVerified: false
          }
        },
        **options
      )
      provider[:create_authorization_url] = lambda do |data|
        "#{Base.authorization_url("https://open.weixin.qq.com/connect/qrconnect", {
          appid: client_id,
          redirect_uri: data[:redirect_uri] || data[:redirectURI],
          response_type: "code",
          scope: Array(data[:scopes] || scopes).join(","),
          state: data[:state],
          lang: options[:lang]
        })}#wechat_redirect"
      end
      provider
    end
  end
end
