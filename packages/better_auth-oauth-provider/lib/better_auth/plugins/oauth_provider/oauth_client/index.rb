# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def oauth_assert_owned_client!(client, session, config = nil)
      data = OAuthProtocol.stringify_keys(client)
      return if data["userId"] && data["userId"] == session[:user]["id"]

      if data["referenceId"] && config && config[:client_reference].respond_to?(:call)
        reference_id = config[:client_reference].call({user: session[:user], session: session[:session]})
        return if data["referenceId"] == reference_id
      end

      raise APIError.new("NOT_FOUND", message: "client not found")
    end

    def oauth_assert_client_privilege!(ctx, config, session, action)
      callback = config[:client_privileges]
      return unless callback.respond_to?(:call)

      allowed = callback.call({
        headers: ctx.headers,
        action: action,
        session: session[:session],
        user: session[:user]
      })
      raise APIError.new("UNAUTHORIZED") unless allowed
    end

    def oauth_client_reference(config, session)
      return nil unless session && config[:client_reference].respond_to?(:call)

      config[:client_reference].call({user: session[:user], session: session[:session]})
    end

    def oauth_client_update_data(source, admin: false)
      update = {}
      update["name"] = source["client_name"] || source["name"] if source.key?("client_name") || source.key?("name")
      update["uri"] = source["client_uri"] if source.key?("client_uri")
      update["icon"] = source["logo_uri"] if source.key?("logo_uri")
      if source.key?("redirect_uris")
        redirects = Array(source["redirect_uris"]).map(&:to_s)
        update["redirectUris"] = redirects
        update["redirectUrls"] = redirects.join(",")
      end
      update["postLogoutRedirectUris"] = Array(source["post_logout_redirect_uris"]).map(&:to_s) if source.key?("post_logout_redirect_uris")
      update["grantTypes"] = Array(source["grant_types"]).map(&:to_s) if source.key?("grant_types")
      update["responseTypes"] = Array(source["response_types"]).map(&:to_s) if source.key?("response_types")
      update["scopes"] = OAuthProtocol.parse_scopes(source["scope"] || source["scopes"]) if source.key?("scope") || source.key?("scopes")
      update["enableEndSession"] = !!(source["enable_end_session"] || source["enableEndSession"]) if source.key?("enable_end_session") || source.key?("enableEndSession")
      update["skipConsent"] = !!(source["skip_consent"] || source["skipConsent"]) if admin && (source.key?("skip_consent") || source.key?("skipConsent"))
      update["clientSecretExpiresAt"] = source["client_secret_expires_at"] if admin && source.key?("client_secret_expires_at")
      update["subjectType"] = source["subject_type"] || source["subjectType"] if admin && (source.key?("subject_type") || source.key?("subjectType"))
      update["metadata"] = source["metadata"] if source.key?("metadata")
      update
    end

    def oauth_public_client_response(client)
      data = OAuthProtocol.stringify_keys(client)
      {
        client_id: data["clientId"],
        client_name: data["name"],
        client_uri: data["uri"],
        logo_uri: data["icon"],
        contacts: data["contacts"] || [],
        tos_uri: data["tos"],
        policy_uri: data["policy"]
      }.compact
    end
  end
end
