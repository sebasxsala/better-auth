# frozen_string_literal: true

module BetterAuth
  module Routes
    def self.list_accounts
      Endpoint.new(path: "/list-accounts", method: "GET") do |ctx|
        session = current_session(ctx)
        accounts = ctx.context.internal_adapter.find_accounts(session[:user]["id"]).map do |account|
          parsed = Schema.parse_output(ctx.context.options, "account", account)
          scope = parsed.delete("scope")
          parsed.merge("scopes" => scope.to_s.empty? ? [] : scope.to_s.split(","))
        end
        ctx.json(accounts)
      end
    end

    def self.unlink_account
      Endpoint.new(path: "/unlink-account", method: "POST") do |ctx|
        session = current_session(ctx, sensitive: true)
        body = normalize_hash(ctx.body)
        accounts = ctx.context.internal_adapter.find_accounts(session[:user]["id"])
        if accounts.length == 1 && !ctx.context.options.account.dig(:account_linking, :allow_unlinking_all)
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["FAILED_TO_UNLINK_LAST_ACCOUNT"])
        end

        provider_id = body["providerId"] || body["provider_id"]
        account_id = body["accountId"] || body["account_id"]
        account = accounts.find do |entry|
          entry["providerId"] == provider_id && (account_id.to_s.empty? || entry["accountId"] == account_id)
        end
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["ACCOUNT_NOT_FOUND"]) unless account

        ctx.context.internal_adapter.delete_account(account["id"])
        ctx.json({status: true})
      end
    end

    def self.get_access_token
      Endpoint.new(path: "/get-access-token", method: "POST") do |ctx|
        session = current_session(ctx, allow_nil: true)
        body = normalize_hash(ctx.body)
        user_id = session&.dig(:user, "id") || body["userId"] || body["user_id"]
        raise APIError.new("UNAUTHORIZED") if user_id.to_s.empty?

        provider_id = body["providerId"] || body["provider_id"]
        provider = social_provider(ctx.context, provider_id)
        raise APIError.new("BAD_REQUEST", message: "Provider #{provider_id} is not supported.") unless provider

        account = find_provider_account(ctx, user_id, provider_id, body["accountId"] || body["account_id"])
        raise APIError.new("BAD_REQUEST", message: "Account not found") unless account

        if account["refreshToken"] && access_token_expired?(account) && provider_callable(provider, :refresh_access_token)
          tokens = call_provider(provider, :refresh_access_token, account["refreshToken"])
          update_account_tokens(ctx, account, tokens)
          account = account.merge(token_hash(tokens))
        end

        ctx.json({
          accessToken: account["accessToken"],
          accessTokenExpiresAt: account["accessTokenExpiresAt"],
          scopes: account["scopes"] || (account["scope"].to_s.empty? ? [] : account["scope"].to_s.split(",")),
          idToken: account["idToken"]
        })
      end
    end

    def self.refresh_token
      Endpoint.new(path: "/refresh-token", method: "POST") do |ctx|
        session = current_session(ctx, allow_nil: true)
        body = normalize_hash(ctx.body)
        user_id = session&.dig(:user, "id") || body["userId"] || body["user_id"]
        raise APIError.new("BAD_REQUEST", message: "Either userId or session is required") if user_id.to_s.empty?

        provider_id = body["providerId"] || body["provider_id"]
        provider = social_provider(ctx.context, provider_id)
        raise APIError.new("BAD_REQUEST", message: "Provider #{provider_id} not found.") unless provider
        raise APIError.new("BAD_REQUEST", message: "Provider #{provider_id} does not support token refreshing.") unless provider_callable(provider, :refresh_access_token)

        account = find_provider_account(ctx, user_id, provider_id, body["accountId"] || body["account_id"])
        raise APIError.new("BAD_REQUEST", message: "Account not found") unless account
        raise APIError.new("BAD_REQUEST", message: "Refresh token not found") if account["refreshToken"].to_s.empty?

        tokens = call_provider(provider, :refresh_access_token, account["refreshToken"])
        update_account_tokens(ctx, account, tokens)
        values = token_hash(tokens)
        ctx.json({
          accessToken: values["accessToken"],
          refreshToken: values["refreshToken"],
          accessTokenExpiresAt: values["accessTokenExpiresAt"],
          refreshTokenExpiresAt: values["refreshTokenExpiresAt"],
          scope: Array(values["scopes"]).join(","),
          idToken: values["idToken"] || account["idToken"],
          providerId: account["providerId"],
          accountId: account["accountId"]
        })
      end
    end

    def self.account_info
      Endpoint.new(path: "/account-info", method: "GET") do |ctx|
        session = current_session(ctx)
        account_id = fetch_value(ctx.query, "accountId")
        account = if account_id
          ctx.context.internal_adapter.find_accounts(session[:user]["id"]).find do |entry|
            entry["id"] == account_id || entry["accountId"] == account_id
          end
        end
        raise APIError.new("BAD_REQUEST", message: "Account not found") unless account && account["userId"] == session[:user]["id"]

        provider = social_provider(ctx.context, account["providerId"])
        raise APIError.new("INTERNAL_SERVER_ERROR", message: "Provider account provider is #{account["providerId"]} but it is not configured") unless provider
        raise APIError.new("BAD_REQUEST", message: "Access token not found") if account["accessToken"].to_s.empty?

        info = call_provider(provider, :get_user_info, {
          accessToken: account["accessToken"],
          access_token: account["accessToken"],
          idToken: account["idToken"],
          scopes: account["scope"].to_s.split(",")
        })
        ctx.json(info)
      end
    end

    def self.social_provider(context, provider_id)
      provider = context.social_providers[provider_id.to_sym] || context.social_providers[provider_id.to_s]
      return provider.merge(id: provider_id.to_s) if provider.is_a?(Hash) && !provider.key?(:id) && !provider.key?("id")

      provider
    end

    def self.find_provider_account(ctx, user_id, provider_id, account_id = nil)
      ctx.context.internal_adapter.find_accounts(user_id).find do |account|
        account["providerId"] == provider_id && (account_id.to_s.empty? || account["id"] == account_id || account["accountId"] == account_id)
      end
    end

    def self.access_token_expired?(account)
      value = account["accessTokenExpiresAt"]
      value && value < Time.now + 5
    end

    def self.update_account_tokens(ctx, account, tokens)
      ctx.context.internal_adapter.update_account(account["id"], token_hash(tokens))
    end

    def self.token_hash(tokens)
      data = normalize_hash(tokens || {})
      data["scope"] = Array(data.delete("scopes")).join(",") if data.key?("scopes")
      data
    end

    def self.provider_callable(provider, key)
      provider.respond_to?(key) || (provider.is_a?(Hash) && (provider[key] || provider[key.to_s]))
    end

    def self.call_provider(provider, key, *arguments)
      return provider.public_send(key, *arguments) if provider.respond_to?(key)

      callable = provider[key] || provider[key.to_s]
      callable.respond_to?(:call) ? callable.call(*arguments) : callable
    end
  end
end
