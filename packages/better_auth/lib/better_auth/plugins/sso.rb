# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "securerandom"
require "uri"

module BetterAuth
  module Plugins
    module_function

    SSO_ERROR_CODES = {
      "PROVIDER_NOT_FOUND" => "No provider found",
      "INVALID_STATE" => "Invalid state",
      "SAML_RESPONSE_REPLAYED" => "SAML response has already been used"
    }.freeze

    def sso(options = {})
      config = normalize_hash(options)
      Plugin.new(
        id: "sso",
        init: ->(_ctx) { {options: {advanced: {disable_origin_check: ["/sso/saml2/callback", "/sso/saml2/sp/acs"]}}} },
        schema: sso_schema(config),
        endpoints: {
          sp_metadata: sso_sp_metadata_endpoint,
          register_sso_provider: sso_register_provider_endpoint,
          sign_in_sso: sso_sign_in_endpoint,
          callback_sso: sso_oidc_callback_endpoint,
          callback_sso_saml: sso_saml_callback_endpoint,
          acs_endpoint: sso_saml_acs_endpoint,
          list_sso_providers: sso_list_providers_endpoint,
          get_sso_provider: sso_get_provider_endpoint,
          update_sso_provider: sso_update_provider_endpoint,
          delete_sso_provider: sso_delete_provider_endpoint,
          request_domain_verification: sso_request_domain_verification_endpoint(config),
          verify_domain: sso_verify_domain_endpoint(config)
        },
        error_codes: SSO_ERROR_CODES,
        options: config
      )
    end

    def sso_schema(config = {})
      {
        ssoProvider: {
          model_name: config[:model_name] || "ssoProviders",
          fields: {
            issuer: {type: "string", required: true},
            oidcConfig: {type: "string", required: false},
            samlConfig: {type: "string", required: false},
            userId: {type: "string", required: true},
            providerId: {type: "string", required: true, unique: true},
            domain: {type: "string", required: true},
            domainVerified: {type: "boolean", required: false, default_value: false},
            domainVerificationToken: {type: "string", required: false},
            organizationId: {type: "string", required: false}
          }
        }
      }
    end

    def sso_discover_oidc_config(issuer:, fetch: nil)
      document = if fetch
        fetch.call("#{issuer.to_s.sub(%r{/+\z}, "")}/.well-known/openid-configuration")
      else
        uri = URI("#{issuer.to_s.sub(%r{/+\z}, "")}/.well-known/openid-configuration")
        JSON.parse(Net::HTTP.get(uri))
      end
      document = normalize_hash(document)
      valid = document[:issuer] == issuer &&
        !document[:authorization_endpoint].to_s.empty? &&
        !document[:token_endpoint].to_s.empty?
      raise APIError.new("BAD_REQUEST", message: "Invalid OIDC discovery document") unless valid

      document
    rescue APIError
      raise
    rescue
      raise APIError.new("BAD_REQUEST", message: "Invalid OIDC discovery document")
    end

    def sso_register_provider_endpoint
      Endpoint.new(path: "/sso/register", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        provider_id = body[:provider_id].to_s
        raise APIError.new("BAD_REQUEST", message: "providerId is required") if provider_id.empty?
        if ctx.context.adapter.find_one(model: "ssoProvider", where: [{field: "providerId", value: provider_id}])
          raise APIError.new("BAD_REQUEST", message: "Provider already exists")
        end

        provider = ctx.context.adapter.create(
          model: "ssoProvider",
          data: {
            providerId: provider_id,
            issuer: body[:issuer].to_s,
            domain: body[:domain].to_s.downcase,
            oidcConfig: body[:oidc_config],
            samlConfig: body[:saml_config],
            userId: session.fetch(:user).fetch("id"),
            organizationId: body[:organization_id],
            domainVerified: body[:domain_verified] || false
          }
        )
        ctx.json(sso_sanitize_provider(provider, ctx.context))
      end
    end

    def sso_list_providers_endpoint
      Endpoint.new(path: "/sso/providers", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        providers = ctx.context.adapter.find_many(model: "ssoProvider")
          .select { |provider| sso_provider_access?(provider, session.fetch(:user).fetch("id")) }
          .map { |provider| sso_sanitize_provider(provider, ctx.context) }
        ctx.json({providers: providers})
      end
    end

    def sso_get_provider_endpoint
      Endpoint.new(path: "/sso/providers/:providerId", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        provider = sso_find_provider!(ctx, sso_fetch(ctx.params, :provider_id))
        raise APIError.new("FORBIDDEN", message: "Access denied") unless sso_provider_access?(provider, session.fetch(:user).fetch("id"))

        ctx.json(sso_sanitize_provider(provider, ctx.context))
      end
    end

    def sso_update_provider_endpoint
      Endpoint.new(path: "/sso/providers/:providerId", method: "PATCH") do |ctx|
        session = Routes.current_session(ctx)
        provider = sso_find_provider!(ctx, sso_fetch(ctx.params, :provider_id))
        raise APIError.new("FORBIDDEN", message: "Access denied") unless sso_provider_access?(provider, session.fetch(:user).fetch("id"))

        body = normalize_hash(ctx.body)
        update = {}
        update[:issuer] = body[:issuer] if body.key?(:issuer)
        update[:domain] = body[:domain].to_s.downcase if body.key?(:domain)
        update[:domainVerified] = false if body.key?(:domain)
        update[:oidcConfig] = body[:oidc_config] if body.key?(:oidc_config)
        update[:samlConfig] = body[:saml_config] if body.key?(:saml_config)
        updated = ctx.context.adapter.update(model: "ssoProvider", where: [{field: "id", value: provider.fetch("id")}], update: update)
        ctx.json(sso_sanitize_provider(updated, ctx.context))
      end
    end

    def sso_delete_provider_endpoint
      Endpoint.new(path: "/sso/providers/:providerId", method: "DELETE") do |ctx|
        session = Routes.current_session(ctx)
        provider = sso_find_provider!(ctx, sso_fetch(ctx.params, :provider_id))
        raise APIError.new("FORBIDDEN", message: "Access denied") unless sso_provider_access?(provider, session.fetch(:user).fetch("id"))

        ctx.context.adapter.delete(model: "ssoProvider", where: [{field: "id", value: provider.fetch("id")}])
        ctx.json({success: true})
      end
    end

    def sso_sign_in_endpoint
      Endpoint.new(path: "/sign-in/sso", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        provider = sso_select_provider(ctx, body)
        state_data = {
          providerId: provider.fetch("providerId"),
          callbackURL: body[:callback_url] || "/",
          errorURL: body[:error_callback_url],
          newUserURL: body[:new_user_callback_url],
          requestSignUp: body[:request_sign_up]
        }

        if provider["samlConfig"]
          relay_state = BetterAuth::Crypto.sign_jwt(state_data.merge(nonce: SecureRandom.hex(8)), ctx.context.secret, expires_in: 600)
          url = sso_saml_authorization_url(provider, relay_state)
        else
          state = BetterAuth::Crypto.sign_jwt(state_data, ctx.context.secret, expires_in: 600)
          url = sso_oidc_authorization_url(provider, ctx, state)
        end
        ctx.json({url: url, redirect: true})
      end
    end

    def sso_oidc_callback_endpoint
      Endpoint.new(path: "/sso/callback/:providerId", method: "GET") do |ctx|
        state = sso_verify_state(ctx.query[:state] || ctx.query["state"], ctx.context.secret)
        next ctx.redirect("#{ctx.context.base_url}/error?error=invalid_state") unless state

        provider = sso_find_provider!(ctx, sso_fetch(ctx.params, :provider_id))
        oidc_config = normalize_hash(provider["oidcConfig"] || {})
        token_callback = oidc_config[:get_token]
        user_callback = oidc_config[:get_user_info]
        tokens = token_callback ? token_callback.call(code: ctx.query[:code] || ctx.query["code"]) : {accessToken: "access-token"}
        user_info = user_callback ? user_callback.call(tokens) : {}
        user = sso_find_or_create_user(ctx, provider, user_info)
        session = ctx.context.internal_adapter.create_session(user.fetch("id"))
        Cookies.set_session_cookie(ctx, {session: session, user: user})
        redirect_to = (state["newUserURL"] && !state["newUserURL"].to_s.empty?) ? state["newUserURL"] : state["callbackURL"]
        sso_redirect(ctx, redirect_to || "/")
      end
    end

    def sso_saml_callback_endpoint
      Endpoint.new(path: "/sso/saml2/callback/:providerId", method: ["GET", "POST"], metadata: {allowed_media_types: ["application/json", "application/x-www-form-urlencoded"]}) do |ctx|
        sso_handle_saml_response(ctx)
      end
    end

    def sso_saml_acs_endpoint
      Endpoint.new(path: "/sso/saml2/sp/acs/:providerId", method: "POST", metadata: {allowed_media_types: ["application/json", "application/x-www-form-urlencoded"]}) do |ctx|
        sso_handle_saml_response(ctx)
      end
    end

    def sso_sp_metadata_endpoint
      Endpoint.new(path: "/sso/saml2/sp/metadata", method: "GET") do |ctx|
        provider = sso_find_provider!(ctx, sso_fetch(ctx.query, :provider_id))
        metadata = "<EntityDescriptor entityID=\"#{ctx.context.base_url}/sso/saml2/sp/metadata\"><SPSSODescriptor /></EntityDescriptor>"
        if (ctx.query[:format] || ctx.query["format"]) == "json"
          ctx.json({providerId: provider.fetch("providerId"), metadata: metadata})
        else
          ctx.set_header("content-type", "application/samlmetadata+xml")
          ctx.json(metadata)
        end
      end
    end

    def sso_request_domain_verification_endpoint(config)
      Endpoint.new(path: "/sso/request-domain-verification", method: "POST") do |ctx|
        Routes.current_session(ctx)
        provider = sso_find_provider!(ctx, normalize_hash(ctx.body)[:provider_id])
        token = "_better-auth-sso-verification-#{provider.fetch("providerId")}-#{SecureRandom.hex(16)}"
        updated = ctx.context.adapter.update(model: "ssoProvider", where: [{field: "id", value: provider.fetch("id")}], update: {domainVerificationToken: token, domainVerified: false})
        config.dig(:domain_verification, :request)&.call(provider: updated, token: token, context: ctx)
        ctx.json({success: true, token: token}, status: 201)
      end
    end

    def sso_verify_domain_endpoint(config)
      Endpoint.new(path: "/sso/verify-domain", method: "POST") do |ctx|
        Routes.current_session(ctx)
        provider = sso_find_provider!(ctx, normalize_hash(ctx.body)[:provider_id])
        token = provider["domainVerificationToken"].to_s
        verifier = config.dig(:domain_verification, :verify)
        verified = verifier ? verifier.call(domain: provider.fetch("domain"), token: token, provider: provider, context: ctx) : true
        raise APIError.new("BAD_REQUEST", message: "Unable to verify domain ownership") unless verified

        ctx.context.adapter.update(model: "ssoProvider", where: [{field: "id", value: provider.fetch("id")}], update: {domainVerified: true, domainVerificationToken: nil})
        ctx.json({success: true})
      end
    end

    def sso_handle_saml_response(ctx)
      provider = sso_find_provider!(ctx, sso_fetch(ctx.params, :provider_id))
      relay_state = sso_fetch(ctx.body, :relay_state) || sso_fetch(ctx.query, :relay_state)
      state = sso_verify_state(relay_state, ctx.context.secret) || {}
      assertion = sso_parse_saml_response(sso_fetch(ctx.body, :saml_response))
      assertion_id = assertion[:id] || assertion["id"] || assertion[:email]
      replay_key = "sso-saml-assertion:#{provider.fetch("providerId")}:#{assertion_id}"
      if ctx.context.internal_adapter.find_verification_value(replay_key)
        raise APIError.new("BAD_REQUEST", message: SSO_ERROR_CODES.fetch("SAML_RESPONSE_REPLAYED"))
      end
      ctx.context.internal_adapter.create_verification_value(identifier: replay_key, value: "used", expiresAt: Time.now + 300)

      user = sso_find_or_create_user(ctx, provider, assertion)
      session = ctx.context.internal_adapter.create_session(user.fetch("id"))
      Cookies.set_session_cookie(ctx, {session: session, user: user})
      callback_url = state["callbackURL"] || "/"
      callback_url = "/" unless ctx.context.trusted_origin?(callback_url, allow_relative_paths: true)
      sso_redirect(ctx, callback_url)
    end

    def sso_find_or_create_user(ctx, provider, user_info)
      user_info = normalize_hash(user_info)
      email = user_info[:email].to_s.downcase
      found = ctx.context.internal_adapter.find_user_by_email(email)
      return found[:user] if found

      user = ctx.context.internal_adapter.create_user(
        email: email,
        name: user_info[:name] || email,
        emailVerified: user_info.key?(:email_verified) ? user_info[:email_verified] : true,
        image: user_info[:image]
      )
      ctx.context.internal_adapter.create_account(
        accountId: (user_info[:id] || user.fetch("id")).to_s,
        providerId: "sso:#{provider.fetch("providerId")}",
        userId: user.fetch("id")
      )
      user
    end

    def sso_parse_saml_response(value)
      JSON.parse(Base64.decode64(value.to_s), symbolize_names: true)
    rescue
      raise APIError.new("BAD_REQUEST", message: "Invalid SAML response")
    end

    def sso_verify_state(value, secret)
      BetterAuth::Crypto.verify_jwt(value.to_s, secret)
    rescue
      nil
    end

    def sso_oidc_authorization_url(provider, ctx, state)
      config = normalize_hash(provider["oidcConfig"] || {})
      endpoint = config[:authorization_endpoint] || config[:authorization_url]
      query = {
        client_id: config[:client_id],
        response_type: "code",
        redirect_uri: "#{ctx.context.base_url}/sso/callback/#{provider.fetch("providerId")}",
        scope: Array(config[:scope] || config[:scopes] || ["openid", "email", "profile"]).join(" "),
        state: state
      }
      "#{endpoint}?#{URI.encode_www_form(query)}"
    end

    def sso_saml_authorization_url(provider, relay_state)
      config = normalize_hash(provider["samlConfig"] || {})
      query = {
        SAMLRequest: Base64.strict_encode64(JSON.generate({providerId: provider.fetch("providerId")})),
        RelayState: relay_state
      }
      "#{config[:entry_point]}?#{URI.encode_www_form(query)}"
    end

    def sso_select_provider(ctx, body)
      providers = ctx.context.adapter.find_many(model: "ssoProvider")
      provider = if body[:provider_id]
        providers.find { |entry| entry["providerId"] == body[:provider_id].to_s }
      elsif body[:issuer]
        providers.find { |entry| entry["issuer"] == body[:issuer].to_s }
      else
        domain = body[:email].to_s.split("@").last.to_s.downcase
        providers.find { |entry| sso_email_domain_matches?(domain, entry["domain"]) }
      end
      raise APIError.new("NOT_FOUND", message: SSO_ERROR_CODES.fetch("PROVIDER_NOT_FOUND")) unless provider

      provider
    end

    def sso_email_domain_matches?(email_domain, provider_domain)
      provider_domain.to_s.split(",").map { |value| value.strip.downcase }.reject(&:empty?).any? do |domain|
        email_domain == domain || email_domain.end_with?(".#{domain}")
      end
    end

    def sso_find_provider!(ctx, provider_id)
      provider = ctx.context.adapter.find_one(model: "ssoProvider", where: [{field: "providerId", value: provider_id.to_s}])
      raise APIError.new("NOT_FOUND", message: SSO_ERROR_CODES.fetch("PROVIDER_NOT_FOUND")) unless provider

      provider
    end

    def sso_provider_access?(provider, user_id)
      provider["userId"] == user_id || provider["organizationId"].nil?
    end

    def sso_sanitize_provider(provider, context)
      data = provider.dup
      data["oidcConfig"] = sso_sanitize_config(data["oidcConfig"])
      data["samlConfig"] = sso_sanitize_config(data["samlConfig"])
      data["spMetadataUrl"] = "#{context.base_url}/sso/saml2/sp/metadata?providerId=#{URI.encode_www_form_component(data.fetch("providerId"))}"
      data
    end

    def sso_sanitize_config(config)
      data = normalize_hash(config || {})
      data.delete(:client_secret)
      data.each_with_object({}) { |(key, value), result| result[Schema.storage_key(key)] = value unless value.respond_to?(:call) }
    end

    def sso_fetch(data, key)
      compact = key.to_s.delete("_").downcase
      data[key] ||
        data[key.to_s] ||
        data[Schema.storage_key(key)] ||
        data[Schema.storage_key(key).to_sym] ||
        data[compact] ||
        data[compact.to_sym]
    end

    def sso_redirect(ctx, location)
      [302, ctx.response_headers.merge("location" => location), [""]]
    end
  end
end
