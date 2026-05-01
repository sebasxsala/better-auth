# frozen_string_literal: true

require "base64"
require "cgi"
require "json"
require "jwt"
require "net/http"
require "openssl"
require "resolv"
require "securerandom"
require "time"
require "uri"
require "zlib"

module BetterAuth
  module Plugins
    module_function

    remove_method :sso if method_defined?(:sso) || private_method_defined?(:sso)
    singleton_class.remove_method(:sso) if singleton_class.method_defined?(:sso) || singleton_class.private_method_defined?(:sso)

    SSO_ERROR_CODES = {
      "PROVIDER_NOT_FOUND" => "No provider found",
      "INVALID_STATE" => "Invalid state",
      "SAML_RESPONSE_REPLAYED" => "SAML response has already been used",
      "SINGLE_LOGOUT_NOT_ENABLED" => "Single Logout is not enabled",
      "INVALID_LOGOUT_REQUEST" => "Invalid LogoutRequest",
      "INVALID_LOGOUT_RESPONSE" => "Invalid LogoutResponse",
      "LOGOUT_FAILED_AT_IDP" => "Logout failed at IdP",
      "IDP_SLO_NOT_SUPPORTED" => "IdP does not support Single Logout Service"
    }.freeze

    SSO_SAML_SIGNATURE_ALGORITHMS = {
      "rsa-sha1" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      "rsa-sha256" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      "rsa-sha384" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
      "rsa-sha512" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
      "ecdsa-sha256" => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
      "ecdsa-sha384" => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
      "ecdsa-sha512" => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
      "sha1" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      "sha256" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      "sha384" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
      "sha512" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    }.freeze

    SSO_SAML_DIGEST_ALGORITHMS = {
      "sha1" => "http://www.w3.org/2000/09/xmldsig#sha1",
      "sha256" => "http://www.w3.org/2001/04/xmlenc#sha256",
      "sha384" => "http://www.w3.org/2001/04/xmldsig-more#sha384",
      "sha512" => "http://www.w3.org/2001/04/xmlenc#sha512"
    }.freeze

    SSO_SAML_SECURE_SIGNATURE_ALGORITHMS = (SSO_SAML_SIGNATURE_ALGORITHMS.values - ["http://www.w3.org/2000/09/xmldsig#rsa-sha1"]).uniq.freeze
    SSO_SAML_SECURE_DIGEST_ALGORITHMS = (SSO_SAML_DIGEST_ALGORITHMS.values - ["http://www.w3.org/2000/09/xmldsig#sha1"]).uniq.freeze
    SSO_SAML_SECURE_KEY_ENCRYPTION_ALGORITHMS = %w[
      http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
      http://www.w3.org/2009/xmlenc11#rsa-oaep
    ].freeze
    SSO_SAML_SECURE_DATA_ENCRYPTION_ALGORITHMS = %w[
      http://www.w3.org/2001/04/xmlenc#aes128-cbc
      http://www.w3.org/2001/04/xmlenc#aes192-cbc
      http://www.w3.org/2001/04/xmlenc#aes256-cbc
      http://www.w3.org/2009/xmlenc11#aes128-gcm
      http://www.w3.org/2009/xmlenc11#aes192-gcm
      http://www.w3.org/2009/xmlenc11#aes256-gcm
    ].freeze
    SSO_DEFAULT_MAX_SAML_RESPONSE_SIZE = 256 * 1024
    SSO_DEFAULT_MAX_SAML_METADATA_SIZE = 100 * 1024
    SSO_SAML_AUTHN_REQUEST_KEY_PREFIX = "saml-authn-request:"
    SSO_DEFAULT_AUTHN_REQUEST_TTL_MS = 5 * 60 * 1000
    SSO_SAML_USED_ASSERTION_KEY_PREFIX = "saml-used-assertion:"
    SSO_DEFAULT_ASSERTION_TTL_MS = 15 * 60 * 1000
    SSO_DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1000
    SSO_SAML_SESSION_KEY_PREFIX = "saml-session:"
    SSO_SAML_SESSION_BY_ID_KEY_PREFIX = "saml-session-by-id:"
    SSO_SAML_LOGOUT_REQUEST_KEY_PREFIX = "saml-logout-request:"
    SSO_SAML_STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
    SSO_DEFAULT_LOGOUT_REQUEST_TTL_MS = 5 * 60 * 1000

    def sso(options = {})
      config = normalize_hash(options)
      if defined?(BetterAuth::SSO::SAML) && defined?(BetterAuth::SSO::SAMLHooks)
        config = BetterAuth::SSO::SAMLHooks.merge_options(BetterAuth::SSO::SAML.sso_options, config)
      end
      endpoints = {
        sp_metadata: sso_sp_metadata_endpoint(config),
        register_sso_provider: sso_register_provider_endpoint(config),
        sign_in_sso: sso_sign_in_endpoint(config),
        callback_sso: sso_oidc_callback_endpoint(config),
        callback_sso_shared: sso_oidc_shared_callback_endpoint(config),
        callback_sso_saml: sso_saml_callback_endpoint(config),
        acs_endpoint: sso_saml_acs_endpoint(config),
        slo_endpoint: sso_saml_slo_endpoint(config),
        initiate_slo: sso_initiate_slo_endpoint(config),
        list_sso_providers: sso_list_providers_endpoint,
        get_sso_provider: sso_get_provider_endpoint,
        update_sso_provider: sso_update_provider_endpoint,
        delete_sso_provider: sso_delete_provider_endpoint
      }
      if config.dig(:domain_verification, :enabled)
        endpoints[:request_domain_verification] = sso_request_domain_verification_endpoint(config)
        endpoints[:verify_domain] = sso_verify_domain_endpoint(config)
      end
      Plugin.new(
        id: "sso",
        init: ->(_ctx) { {options: {advanced: {disable_origin_check: ["/sso/saml2/callback", "/sso/saml2/sp/acs", "/sso/saml2/sp/slo"]}}} },
        schema: sso_schema(config),
        endpoints: endpoints,
        error_codes: SSO_ERROR_CODES,
        options: config
      )
    end

    def sso_schema(config = {})
      fields = {
        issuer: {type: "string", required: true},
        oidcConfig: {type: "string", required: false},
        samlConfig: {type: "string", required: false},
        userId: {type: "string", required: true},
        providerId: {type: "string", required: true, unique: true},
        domain: {type: "string", required: true},
        organizationId: {type: "string", required: false}
      }
      if config.dig(:domain_verification, :enabled)
        fields[:domainVerified] = {type: "boolean", required: false, default_value: false}
      end
      {
        ssoProvider: {
          model_name: config[:model_name] || "ssoProviders",
          fields: fields
        }
      }
    end

    def sso_discover_oidc_config(issuer:, fetch: nil, existing_config: nil, discovery_endpoint: nil, trusted_origin: nil, timeout: nil)
      existing = normalize_hash(existing_config || {})
      discovery_url = discovery_endpoint || existing[:discovery_endpoint] || "#{issuer.to_s.sub(%r{/+\z}, "")}/.well-known/openid-configuration"
      if trusted_origin && !trusted_origin.call(discovery_url)
        raise APIError.new("BAD_REQUEST", message: "OIDC discovery endpoint is not trusted")
      end
      document = if fetch
        fetch.call(discovery_url)
      else
        uri = URI(discovery_url)
        JSON.parse(Net::HTTP.get(uri))
      end
      document = normalize_hash(document)
      valid = document[:issuer].to_s.sub(%r{/+\z}, "") == issuer.to_s.sub(%r{/+\z}, "") &&
        !document[:authorization_endpoint].to_s.empty? &&
        !document[:token_endpoint].to_s.empty? &&
        !document[:jwks_uri].to_s.empty?
      raise APIError.new("BAD_REQUEST", message: "Invalid OIDC discovery document") unless valid

      authorization_endpoint = sso_normalize_discovery_url(document[:authorization_endpoint], issuer, trusted_origin)
      token_endpoint = sso_normalize_discovery_url(document[:token_endpoint], issuer, trusted_origin)
      jwks_endpoint = sso_normalize_discovery_url(document[:jwks_uri], issuer, trusted_origin)
      user_info_endpoint = document[:userinfo_endpoint] && sso_normalize_discovery_url(document[:userinfo_endpoint], issuer, trusted_origin)
      auth_methods = Array(document[:token_endpoint_auth_methods_supported])
      token_endpoint_authentication = if existing[:token_endpoint_authentication]
        existing[:token_endpoint_authentication]
      elsif auth_methods.include?("client_secret_post") && !auth_methods.include?("client_secret_basic")
        "client_secret_post"
      else
        "client_secret_basic"
      end

      {
        issuer: existing[:issuer] || document[:issuer],
        discovery_endpoint: existing[:discovery_endpoint] || discovery_url,
        client_id: existing[:client_id],
        authorization_endpoint: existing[:authorization_endpoint] || authorization_endpoint,
        token_endpoint: existing[:token_endpoint] || token_endpoint,
        jwks_endpoint: existing[:jwks_endpoint] || jwks_endpoint,
        user_info_endpoint: existing[:user_info_endpoint] || user_info_endpoint,
        token_endpoint_authentication: token_endpoint_authentication,
        scopes_supported: existing[:scopes_supported] || document[:scopes_supported]
      }.compact
    rescue APIError
      raise
    rescue
      raise APIError.new("BAD_REQUEST", message: "Invalid OIDC discovery document")
    end

    def sso_normalize_discovery_url(value, issuer, trusted_origin)
      uri = URI(value.to_s)
      normalized = if uri.absolute?
        uri.to_s
      else
        issuer_uri = URI(issuer.to_s)
        issuer_base = issuer_uri.to_s.sub(%r{/+\z}, "")
        endpoint = value.to_s.sub(%r{\A/+}, "")
        "#{issuer_base}/#{endpoint}"
      end
      if trusted_origin && !trusted_origin.call(normalized)
        raise APIError.new("BAD_REQUEST", message: "OIDC discovery endpoint is not trusted")
      end

      normalized
    rescue URI::InvalidURIError
      raise APIError.new("BAD_REQUEST", message: "Invalid OIDC discovery document")
    end

    def sso_register_provider_endpoint(config = {})
      Endpoint.new(path: "/sso/register", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        provider_id = body[:provider_id].to_s
        raise APIError.new("BAD_REQUEST", message: "providerId is required") if provider_id.empty?

        limit = sso_provider_limit(session.fetch(:user), config)
        if limit.to_i.zero?
          raise APIError.new("FORBIDDEN", message: "SSO provider registration is disabled")
        end
        providers = ctx.context.adapter.find_many(model: "ssoProvider", where: [{field: "userId", value: session.fetch(:user).fetch("id")}])
        if providers.length >= limit.to_i
          raise APIError.new("FORBIDDEN", message: "You have reached the maximum number of SSO providers")
        end

        sso_validate_url!(body[:issuer], "Invalid issuer. Must be a valid URL")
        sso_validate_organization_membership!(ctx, session.fetch(:user).fetch("id"), body[:organization_id]) if body[:organization_id]
        if ctx.context.adapter.find_one(model: "ssoProvider", where: [{field: "providerId", value: provider_id}])
          raise APIError.new("UNPROCESSABLE_ENTITY", message: "SSO provider with this providerId already exists")
        end

        oidc_config = normalize_hash(body[:oidc_config] || {})
        oidc_config = sso_hydrate_oidc_config(body[:issuer], oidc_config, ctx) if oidc_config.any? && !oidc_config[:skip_discovery]
        oidc_config[:override_user_info] = !!(body[:override_user_info] || config[:default_override_user_info]) if oidc_config.any?
        saml_config = normalize_hash(body[:saml_config] || {})
        sso_validate_saml_config!(saml_config, config) unless saml_config.empty?

        provider = ctx.context.adapter.create(
          model: "ssoProvider",
          data: {
            providerId: provider_id,
            issuer: body[:issuer].to_s,
            domain: body[:domain].to_s.downcase,
            oidcConfig: oidc_config.empty? ? nil : oidc_config,
            samlConfig: saml_config.empty? ? nil : saml_config,
            userId: session.fetch(:user).fetch("id"),
            organizationId: body[:organization_id],
            domainVerified: false
          }
        )
        response = sso_sanitize_provider(provider, ctx.context)
        response[:redirectURI] = sso_oidc_redirect_uri(ctx.context, provider.fetch("providerId"))
        ctx.json(response)
      end
    end

    def sso_list_providers_endpoint
      Endpoint.new(path: "/sso/providers", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        providers = ctx.context.adapter.find_many(model: "ssoProvider")
          .select { |provider| sso_provider_access?(provider, session.fetch(:user).fetch("id"), ctx) }
          .map { |provider| sso_sanitize_provider(provider, ctx.context) }
        ctx.json({providers: providers})
      end
    end

    def sso_get_provider_endpoint
      Endpoint.new(path: "/sso/get-provider", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        provider = sso_find_provider!(ctx, sso_fetch(ctx.query, :provider_id) || sso_fetch(ctx.params, :provider_id))
        raise APIError.new("FORBIDDEN", message: "You don't have access to this provider") unless sso_provider_access?(provider, session.fetch(:user).fetch("id"), ctx)

        ctx.json(sso_sanitize_provider(provider, ctx.context))
      end
    end

    def sso_update_provider_endpoint
      Endpoint.new(path: "/sso/update-provider", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        provider = sso_find_provider!(ctx, sso_fetch(body, :provider_id) || sso_fetch(ctx.params, :provider_id))
        raise APIError.new("FORBIDDEN", message: "You don't have access to this provider") unless sso_provider_access?(provider, session.fetch(:user).fetch("id"), ctx)

        if !body.key?(:issuer) && !body.key?(:domain) && !body.key?(:oidc_config) && !body.key?(:saml_config)
          raise APIError.new("BAD_REQUEST", message: "No fields provided for update")
        end
        sso_validate_url!(body[:issuer], "Invalid issuer. Must be a valid URL") if body.key?(:issuer)
        update = {}
        update[:issuer] = body[:issuer] if body.key?(:issuer)
        update[:domain] = body[:domain].to_s.downcase if body.key?(:domain)
        update[:domainVerified] = false if body.key?(:domain) && body[:domain].to_s.downcase != provider["domain"].to_s
        if body.key?(:oidc_config)
          current = normalize_hash(provider["oidcConfig"] || {})
          raise APIError.new("BAD_REQUEST", message: "Cannot update OIDC config for a provider that doesn't have OIDC configured") if current.empty?

          update[:oidcConfig] = current.merge(normalize_hash(body[:oidc_config]))
        end
        if body.key?(:saml_config)
          current = normalize_hash(provider["samlConfig"] || {})
          raise APIError.new("BAD_REQUEST", message: "Cannot update SAML config for a provider that doesn't have SAML configured") if current.empty?

          update[:samlConfig] = current.merge(normalize_hash(body[:saml_config]))
        end
        updated = ctx.context.adapter.update(model: "ssoProvider", where: [{field: "id", value: provider.fetch("id")}], update: update)
        ctx.json(sso_sanitize_provider(updated, ctx.context))
      end
    end

    def sso_delete_provider_endpoint
      Endpoint.new(path: "/sso/delete-provider", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        provider = sso_find_provider!(ctx, sso_fetch(ctx.body, :provider_id) || sso_fetch(ctx.params, :provider_id))
        raise APIError.new("FORBIDDEN", message: "You don't have access to this provider") unless sso_provider_access?(provider, session.fetch(:user).fetch("id"), ctx)

        ctx.context.adapter.delete(model: "ssoProvider", where: [{field: "id", value: provider.fetch("id")}])
        ctx.json({success: true})
      end
    end

    def sso_sign_in_endpoint(config = {})
      Endpoint.new(path: "/sign-in/sso", method: "POST") do |ctx|
        body = normalize_hash(ctx.body)
        provider = sso_select_provider(ctx, body, config)
        provider_type = body[:provider_type].to_s
        if provider_type == "oidc" && !provider["oidcConfig"]
          raise APIError.new("BAD_REQUEST", message: "OIDC provider is not configured")
        end
        if provider_type == "saml" && !provider["samlConfig"]
          raise APIError.new("BAD_REQUEST", message: "SAML provider is not configured")
        end
        if config.dig(:domain_verification, :enabled) && !(provider.key?("domainVerified") && provider["domainVerified"])
          raise APIError.new("UNAUTHORIZED", message: "Provider domain has not been verified")
        end

        state_data = {
          providerId: provider.fetch("providerId"),
          callbackURL: body[:callback_url] || "/",
          errorURL: body[:error_callback_url],
          newUserURL: body[:new_user_callback_url],
          requestSignUp: body[:request_sign_up]
        }

        if provider["oidcConfig"] && provider_type != "saml"
          provider = sso_ensure_runtime_oidc_provider(ctx, provider, config)
          state = BetterAuth::Crypto.sign_jwt(state_data.merge(sso_oidc_pkce_state(provider)), ctx.context.secret, expires_in: 600)
          url = sso_oidc_authorization_url(provider, ctx, state, config, body)
        elsif provider["samlConfig"]
          relay_state = BetterAuth::Crypto.sign_jwt(state_data.merge(nonce: BetterAuth::Crypto.random_string(16)), ctx.context.secret, expires_in: 600)
          url = sso_saml_authorization_url(provider, relay_state, ctx, config)
          sso_store_saml_authn_request(ctx, provider, url, config)
        else
          raise APIError.new("BAD_REQUEST", message: "OIDC provider is not configured")
        end
        ctx.json({url: url, redirect: true})
      end
    end

    def sso_oidc_callback_endpoint(config = {})
      Endpoint.new(path: "/sso/callback/:providerId", method: "GET") do |ctx|
        sso_handle_oidc_callback(ctx, config, sso_fetch(ctx.params, :provider_id))
      end
    end

    def sso_oidc_shared_callback_endpoint(config = {})
      Endpoint.new(path: "/sso/callback", method: "GET") do |ctx|
        state = sso_verify_state(ctx.query[:state] || ctx.query["state"], ctx.context.secret)
        next ctx.redirect("#{ctx.context.base_url}/error?error=invalid_state") unless state

        sso_handle_oidc_callback(ctx, config, state["providerId"], state: state)
      end
    end

    def sso_handle_oidc_callback(ctx, config, provider_id, state: nil)
      state ||= sso_verify_state(ctx.query[:state] || ctx.query["state"], ctx.context.secret)
      return ctx.redirect("#{ctx.context.base_url}/error?error=invalid_state") unless state

      callback_url = state["callbackURL"] || "/"
      error_url = state["errorURL"] || callback_url
      if ctx.query[:error] || ctx.query["error"]
        error = ctx.query[:error] || ctx.query["error"]
        description = ctx.query[:error_description] || ctx.query["error_description"]
        return sso_redirect(ctx, sso_append_error(error_url, error, description))
      end

      provider = sso_callback_provider(ctx, config, provider_id)
      return sso_redirect(ctx, sso_append_error(error_url, "invalid_provider", "provider not found")) unless provider
      if config.dig(:domain_verification, :enabled) && !(provider.key?("domainVerified") && provider["domainVerified"])
        raise APIError.new("UNAUTHORIZED", message: "Provider domain has not been verified")
      end

      provider = sso_ensure_runtime_oidc_provider(ctx, provider, config)
      oidc_config = normalize_hash(provider["oidcConfig"] || {})
      oidc_config[:issuer] ||= provider["issuer"]
      return sso_redirect(ctx, sso_append_error(error_url, "invalid_provider", "provider not found")) if oidc_config.empty?

      tokens = sso_oidc_tokens(ctx, provider, oidc_config, state, config)
      unless tokens
        return sso_redirect(ctx, sso_append_error(error_url, "invalid_provider", "token_response_not_found"))
      end
      if oidc_config[:user_info_endpoint].to_s.empty? && tokens[:id_token] && oidc_config[:jwks_endpoint].to_s.empty?
        begin
          provider = sso_ensure_runtime_oidc_provider(ctx, provider, config, require_jwks: true)
          oidc_config = normalize_hash(provider["oidcConfig"] || {})
          oidc_config[:issuer] ||= provider["issuer"]
        rescue APIError
          # Fall through to the upstream callback error when JWKS is still unavailable.
        end
      end
      user_info = sso_oidc_user_info(ctx, oidc_config, tokens, config)
      if user_info[:_sso_error]
        return sso_redirect(ctx, sso_append_error(error_url, "invalid_provider", user_info[:_sso_error]))
      end
      if user_info[:email].to_s.empty? || user_info[:id].to_s.empty?
        return sso_redirect(ctx, sso_append_error(error_url, "invalid_provider", "missing_user_info"))
      end
      if config[:disable_implicit_sign_up] && !state["requestSignUp"] && !ctx.context.internal_adapter.find_user_by_email(user_info[:email].to_s.downcase)
        return sso_redirect(ctx, sso_append_error(error_url, "signup disabled"))
      end

      result = sso_find_or_create_user_result(ctx, provider, user_info, config)
      if config[:provision_user].respond_to?(:call) && (result.fetch(:created) || config[:provision_user_on_every_login])
        config[:provision_user].call(user: result.fetch(:user), userInfo: user_info, token: tokens, provider: provider)
      end
      session = ctx.context.internal_adapter.create_session(result.fetch(:user).fetch("id"))
      Cookies.set_session_cookie(ctx, {session: session, user: result.fetch(:user)})
      redirect_to = (result.fetch(:created) && state["newUserURL"].to_s != "") ? state["newUserURL"] : callback_url
      sso_redirect(ctx, redirect_to || "/")
    end

    def sso_saml_callback_endpoint(config)
      Endpoint.new(path: "/sso/saml2/callback/:providerId", method: ["GET", "POST"], metadata: {allowed_media_types: ["application/json", "application/x-www-form-urlencoded"]}) do |ctx|
        sso_handle_saml_response(ctx, config)
      end
    end

    def sso_saml_acs_endpoint(config)
      Endpoint.new(path: "/sso/saml2/sp/acs/:providerId", method: "POST", metadata: {allowed_media_types: ["application/json", "application/x-www-form-urlencoded"]}) do |ctx|
        sso_handle_saml_response(ctx, config)
      end
    end

    def sso_sp_metadata_endpoint(config = {})
      Endpoint.new(path: "/sso/saml2/sp/metadata", method: "GET") do |ctx|
        provider = sso_find_provider!(ctx, sso_fetch(ctx.query, :provider_id))
        metadata = sso_sp_metadata_xml(ctx, provider, config)
        if (ctx.query[:format] || ctx.query["format"]) == "json"
          ctx.json({providerId: provider.fetch("providerId"), metadata: metadata})
        else
          ctx.set_header("content-type", "application/samlmetadata+xml")
          ctx.json(metadata)
        end
      end
    end

    def sso_saml_slo_endpoint(config = {})
      Endpoint.new(path: "/sso/saml2/sp/slo/:providerId", method: ["GET", "POST"], metadata: {allowed_media_types: ["application/json", "application/x-www-form-urlencoded"]}) do |ctx|
        raise APIError.new("BAD_REQUEST", message: "Single Logout is not enabled") unless config.dig(:saml, :enable_single_logout)

        provider = sso_find_provider!(ctx, sso_fetch(ctx.params, :provider_id))
        relay_state = sso_fetch(ctx.body, :relay_state) || sso_fetch(ctx.query, :relay_state)
        if sso_fetch(ctx.body, :saml_response) || sso_fetch(ctx.query, :saml_response)
          sso_process_saml_logout_response(ctx, sso_fetch(ctx.body, :saml_response) || sso_fetch(ctx.query, :saml_response))
          Cookies.delete_session_cookie(ctx)
          next sso_redirect(ctx, sso_safe_slo_redirect_url(ctx, relay_state, provider.fetch("providerId")))
        end

        sso_process_saml_logout_request(ctx, provider, sso_fetch(ctx.body, :saml_request) || sso_fetch(ctx.query, :saml_request))
        response = Base64.strict_encode64("<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_#{BetterAuth::Crypto.random_string(32)}\" Version=\"2.0\" IssueInstant=\"#{Time.now.utc.iso8601}\" Destination=\"#{sso_saml_logout_destination(provider)}\"><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status></samlp:LogoutResponse>")
        if sso_fetch(ctx.body, :saml_request)
          next sso_saml_post_form(sso_saml_logout_destination(provider), "SAMLResponse", response, relay_state)
        end

        sso_redirect(ctx, "#{sso_saml_logout_destination(provider)}?#{URI.encode_www_form(SAMLResponse: response, RelayState: relay_state)}")
      end
    end

    def sso_initiate_slo_endpoint(config = {})
      Endpoint.new(path: "/sso/saml2/logout/:providerId", method: "POST") do |ctx|
        raise APIError.new("BAD_REQUEST", message: "Single Logout is not enabled") unless config.dig(:saml, :enable_single_logout)

        session = Routes.current_session(ctx)
        provider = sso_find_provider!(ctx, sso_fetch(ctx.params, :provider_id))
        destination = sso_saml_logout_destination(provider)
        if destination.to_s.empty?
          raise APIError.new("BAD_REQUEST", message: "IdP does not support Single Logout Service")
        end

        relay_state = sso_fetch(ctx.body, :callback_url) || ctx.context.base_url
        session_token = session.fetch(:session).fetch("token")
        user_email = session.fetch(:user).fetch("email")
        saml_session_key = ctx.context.internal_adapter.find_verification_value("#{SSO_SAML_SESSION_BY_ID_KEY_PREFIX}#{session_token}")&.fetch("value")
        saml_session = saml_session_key && ctx.context.internal_adapter.find_verification_value(saml_session_key)
        saml_record = saml_session ? JSON.parse(saml_session.fetch("value")) : {}
        name_id = saml_record["nameId"] || user_email
        session_index = saml_record["sessionIndex"]

        request_id = "_#{BetterAuth::Crypto.random_string(32)}"
        session_index_xml = session_index.to_s.empty? ? "" : "<samlp:SessionIndex>#{CGI.escapeHTML(session_index.to_s)}</samlp:SessionIndex>"
        request = Base64.strict_encode64("<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"#{request_id}\" Version=\"2.0\" IssueInstant=\"#{Time.now.utc.iso8601}\" Destination=\"#{CGI.escapeHTML(destination.to_s)}\"><saml:NameID>#{CGI.escapeHTML(name_id.to_s)}</saml:NameID>#{session_index_xml}</samlp:LogoutRequest>")
        sso_store_saml_logout_request(ctx, provider, request_id, config)
        ctx.context.internal_adapter.delete_verification_by_identifier(saml_session_key) if saml_session_key
        ctx.context.internal_adapter.delete_verification_by_identifier("#{SSO_SAML_SESSION_BY_ID_KEY_PREFIX}#{session_token}")
        ctx.context.internal_adapter.delete_session(session_token)
        Cookies.delete_session_cookie(ctx)
        sso_redirect(ctx, "#{destination}?#{URI.encode_www_form(SAMLRequest: request, RelayState: relay_state)}")
      end
    end

    def sso_request_domain_verification_endpoint(config)
      Endpoint.new(path: "/sso/request-domain-verification", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        provider = sso_find_provider!(ctx, normalize_hash(ctx.body)[:provider_id])
        sso_authorize_domain_verification!(ctx, provider, session.fetch(:user).fetch("id"))
        if provider.key?("domainVerified") && provider["domainVerified"]
          raise APIError.new("CONFLICT", message: "Domain has already been verified", code: "DOMAIN_VERIFIED")
        end

        identifier = sso_domain_verification_identifier(config, provider.fetch("providerId"))
        active = ctx.context.internal_adapter.find_verification_value(identifier)
        if active && sso_future_time?(active.fetch("expiresAt"))
          next ctx.json({domainVerificationToken: active.fetch("value")}, status: 201)
        end

        token = BetterAuth::Crypto.random_string(24)
        ctx.context.internal_adapter.create_verification_value(identifier: identifier, value: token, expiresAt: Time.now + (7 * 24 * 60 * 60))
        config.dig(:domain_verification, :request)&.call(provider: provider, token: token, context: ctx)
        ctx.json({domainVerificationToken: token}, status: 201)
      end
    end

    def sso_verify_domain_endpoint(config)
      Endpoint.new(path: "/sso/verify-domain", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        provider = sso_find_provider!(ctx, normalize_hash(ctx.body)[:provider_id])
        sso_authorize_domain_verification!(ctx, provider, session.fetch(:user).fetch("id"))
        if provider.key?("domainVerified") && provider["domainVerified"]
          raise APIError.new("CONFLICT", message: "Domain has already been verified", code: "DOMAIN_VERIFIED")
        end

        identifier = sso_domain_verification_identifier(config, provider.fetch("providerId"))
        if identifier.length > 63
          raise APIError.new("BAD_REQUEST", message: "Verification identifier exceeds the DNS label limit of 63 characters", code: "IDENTIFIER_TOO_LONG")
        end
        active = ctx.context.internal_adapter.find_verification_value(identifier)
        if !active || !sso_future_time?(active.fetch("expiresAt"))
          raise APIError.new("NOT_FOUND", message: "No pending domain verification exists", code: "NO_PENDING_VERIFICATION")
        end

        hostname = sso_hostname_from_domain(provider.fetch("domain"))
        raise APIError.new("BAD_REQUEST", message: "Invalid domain", code: "INVALID_DOMAIN") if hostname.to_s.empty?

        records = sso_resolve_txt_records("#{identifier}.#{hostname}", config)
        expected = "#{identifier}=#{active.fetch("value")}"
        unless records.flatten.any? { |record| record.to_s.include?(expected) }
          raise APIError.new("BAD_GATEWAY", message: "Unable to verify domain ownership. Try again later", code: "DOMAIN_VERIFICATION_FAILED")
        end

        ctx.context.adapter.update(model: "ssoProvider", where: [{field: "id", value: provider.fetch("id")}], update: {domainVerified: true})
        ctx.context.internal_adapter.delete_verification_by_identifier(identifier)
        ctx.set_status(204)
        nil
      end
    end

    def sso_handle_saml_response(ctx, config = {})
      provider = sso_find_provider!(ctx, sso_fetch(ctx.params, :provider_id))
      relay_state = sso_fetch(ctx.body, :relay_state) || sso_fetch(ctx.query, :relay_state)
      state = sso_verify_state(relay_state, ctx.context.secret) || {}
      raw_response = sso_fetch(ctx.body, :saml_response)
      max_response_size = config.dig(:saml, :max_response_size) || SSO_DEFAULT_MAX_SAML_RESPONSE_SIZE
      if raw_response.to_s.bytesize > max_response_size
        raise APIError.new("BAD_REQUEST", message: "SAML response exceeds maximum allowed size (#{max_response_size} bytes)")
      end
      in_response_to_error = sso_validate_saml_in_response_to(ctx, config, provider, raw_response, state)
      return in_response_to_error if in_response_to_error

      assertion = sso_parse_saml_response(raw_response, config, provider, ctx)
      assertion[:email_verified] = false unless config[:trust_email_verified]
      sso_validate_saml_timestamp!(sso_saml_timestamp_conditions(assertion), config)
      sso_validate_saml_response!(config, assertion, provider, ctx)
      assertion_id = assertion[:id] || assertion["id"] || assertion[:email]
      replay_key = "#{SSO_SAML_USED_ASSERTION_KEY_PREFIX}#{assertion_id}"
      if ctx.context.internal_adapter.find_verification_value(replay_key)
        raise APIError.new("BAD_REQUEST", message: SSO_ERROR_CODES.fetch("SAML_RESPONSE_REPLAYED"))
      end
      ctx.context.internal_adapter.create_verification_value(identifier: replay_key, value: "used", expiresAt: sso_saml_assertion_replay_expires_at(assertion, config))

      callback_url = state["callbackURL"] || "/"
      callback_url = "/" unless ctx.context.trusted_origin?(callback_url, allow_relative_paths: true)
      email = (assertion[:email] || assertion["email"]).to_s.downcase
      if config[:disable_implicit_sign_up] && !state["requestSignUp"] && !ctx.context.internal_adapter.find_user_by_email(email)
        return sso_redirect(ctx, sso_append_error(callback_url, "signup disabled"))
      end

      result = sso_find_or_create_user_result(ctx, provider, assertion, config)
      user = result.fetch(:user)
      if config[:provision_user].respond_to?(:call) && (result.fetch(:created) || config[:provision_user_on_every_login])
        config[:provision_user].call(user: user, userInfo: assertion, provider: provider)
      end
      session = ctx.context.internal_adapter.create_session(user.fetch("id"))
      sso_store_saml_session(ctx, provider, assertion, session) if config.dig(:saml, :enable_single_logout)
      Cookies.set_session_cookie(ctx, {session: session, user: user})
      sso_redirect(ctx, callback_url)
    end

    def sso_find_or_create_user(ctx, provider, user_info, config = {})
      sso_find_or_create_user_result(ctx, provider, user_info, config).fetch(:user)
    end

    def sso_find_or_create_user_result(ctx, provider, user_info, config = {})
      user_info = normalize_hash(user_info)
      email = user_info[:email].to_s.downcase
      found = ctx.context.internal_adapter.find_user_by_email(email)
      if found
        user = found[:user]
        oidc_config = normalize_hash(provider["oidcConfig"] || {})
        if oidc_config[:override_user_info] || config[:default_override_user_info]
          update = {}
          update[:name] = user_info[:name] if user_info.key?(:name)
          update[:image] = user_info[:image] if user_info.key?(:image)
          update[:emailVerified] = !!user_info[:email_verified] if user_info.key?(:email_verified)
          user = ctx.context.internal_adapter.update_user(user.fetch("id"), update) if update.any?
        end
        created = false
      else
        created = ctx.context.internal_adapter.create_user(
          email: email,
          name: user_info[:name] || email,
          emailVerified: user_info.key?(:email_verified) ? user_info[:email_verified] : false,
          image: user_info[:image]
        )
        ctx.context.internal_adapter.create_account(
          accountId: (user_info[:id] || created.fetch("id")).to_s,
          providerId: "sso:#{provider.fetch("providerId")}",
          userId: created.fetch("id")
        )
        user = created
        created = true
      end
      sso_assign_organization_membership(ctx, provider, user, config)
      {user: user, created: created}
    end

    def sso_validate_saml_response!(config, assertion, provider, ctx)
      validator = config.dig(:saml, :validate_response)
      return unless validator.respond_to?(:call)
      return if validator.call(response: assertion, provider: provider, context: ctx)

      raise APIError.new("BAD_REQUEST", message: "Invalid SAML response")
    end

    def sso_validate_saml_config!(saml_config, plugin_config = {})
      metadata = saml_config[:idp_metadata] || saml_config[:metadata] || saml_config[:idp_metadata_xml]
      max_metadata_size = plugin_config.dig(:saml, :max_metadata_size) || SSO_DEFAULT_MAX_SAML_METADATA_SIZE
      if metadata.to_s.bytesize > max_metadata_size
        raise APIError.new("BAD_REQUEST", message: "IdP metadata exceeds maximum allowed size (#{max_metadata_size} bytes)")
      end

      if saml_config[:entry_point].to_s.empty? && saml_config[:single_sign_on_service].to_s.empty? && metadata.to_s.empty?
        raise APIError.new("BAD_REQUEST", message: "SAML config must include entryPoint, singleSignOnService, or IdP metadata")
      end

      sso_validate_saml_algorithms!(
        metadata.to_s,
        on_deprecated: plugin_config.dig(:saml, :algorithms, :on_deprecated) || saml_config[:on_deprecated_algorithm] || "warn",
        allowed_signature_algorithms: plugin_config.dig(:saml, :algorithms, :allowed_signature_algorithms) || saml_config[:allowed_signature_algorithms],
        allowed_digest_algorithms: plugin_config.dig(:saml, :algorithms, :allowed_digest_algorithms) || saml_config[:allowed_digest_algorithms],
        allowed_key_encryption_algorithms: plugin_config.dig(:saml, :algorithms, :allowed_key_encryption_algorithms) || saml_config[:allowed_key_encryption_algorithms],
        allowed_data_encryption_algorithms: plugin_config.dig(:saml, :algorithms, :allowed_data_encryption_algorithms) || saml_config[:allowed_data_encryption_algorithms]
      )
    end

    def sso_sp_metadata_xml(ctx, provider, config = {})
      provider_id = provider.fetch("providerId")
      saml_config = normalize_hash(provider["samlConfig"] || {})
      entity_id = saml_config.dig(:sp_metadata, :entity_id) || saml_config[:audience] || "#{ctx.context.base_url}/sso/saml2/sp/metadata?providerId=#{URI.encode_www_form_component(provider_id)}"
      acs_url = saml_config[:callback_url] || "#{ctx.context.base_url}/sso/saml2/sp/acs/#{URI.encode_www_form_component(provider_id)}"
      authn_requests_signed = !!saml_config[:authn_requests_signed]
      want_assertions_signed = saml_config.key?(:want_assertions_signed) ? !!saml_config[:want_assertions_signed] : true
      slo = if config.dig(:saml, :enable_single_logout)
        location = "#{ctx.context.base_url}/sso/saml2/sp/slo/#{URI.encode_www_form_component(provider_id)}"
        "<SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"#{location}\" /><SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"#{location}\" />"
      end

      "<EntityDescriptor entityID=\"#{entity_id}\"><SPSSODescriptor AuthnRequestsSigned=\"#{authn_requests_signed}\" WantAssertionsSigned=\"#{want_assertions_signed}\">#{slo}<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"#{acs_url}\" index=\"0\" /></SPSSODescriptor></EntityDescriptor>"
    end

    def sso_saml_logout_destination(provider)
      saml_config = normalize_hash(provider["samlConfig"] || {})
      direct = saml_config[:single_logout_service] ||
        saml_config[:single_logout_service_url] ||
        saml_config[:idp_slo_service_url] ||
        saml_config[:logout_url]
      return direct unless direct.to_s.empty?

      idp_metadata = normalize_hash(saml_config[:idp_metadata] || {})
      structured = idp_metadata[:single_logout_service] || saml_config[:single_logout_service]
      structured = structured.first if structured.is_a?(Array)
      structured = normalize_hash(structured) if structured.is_a?(Hash)
      return structured[:location] if structured.is_a?(Hash) && !structured[:location].to_s.empty?

      metadata = idp_metadata[:metadata] || saml_config[:metadata] || saml_config[:idp_metadata_xml]
      metadata.to_s[/<[^>]*SingleLogoutService\b[^>]*\bLocation=['"]([^'"]+)['"]/, 1]
    end

    def sso_store_saml_session(ctx, provider, assertion, session)
      name_id = assertion[:name_id] || assertion[:nameid] || assertion[:email]
      session_index = assertion[:session_index] || assertion[:sessionindex] || assertion[:id]
      return if name_id.to_s.empty? || session_index.to_s.empty?

      record = {
        providerId: provider.fetch("providerId"),
        sessionToken: session.fetch("token"),
        userId: session.fetch("userId"),
        nameId: name_id.to_s,
        sessionIndex: session_index.to_s
      }
      expires_at = session["expiresAt"] || Time.now + (SSO_DEFAULT_ASSERTION_TTL_MS / 1000.0)
      value = JSON.generate(record)
      session_identifier = "#{SSO_SAML_SESSION_KEY_PREFIX}#{provider.fetch("providerId")}:#{name_id}"
      ctx.context.internal_adapter.create_verification_value(
        identifier: session_identifier,
        value: value,
        expiresAt: expires_at
      )
      ctx.context.internal_adapter.create_verification_value(
        identifier: "#{SSO_SAML_SESSION_BY_ID_KEY_PREFIX}#{session.fetch("token")}",
        value: session_identifier,
        expiresAt: expires_at
      )
    end

    def sso_process_saml_logout_request(ctx, provider, raw_request)
      data = sso_parse_saml_logout_request(raw_request)
      return if data[:name_id].to_s.empty?

      session_identifier = "#{SSO_SAML_SESSION_KEY_PREFIX}#{provider.fetch("providerId")}:#{data[:name_id]}"
      verification = ctx.context.internal_adapter.find_verification_value(session_identifier)
      return unless verification

      record = JSON.parse(verification.fetch("value"))
      session_token = record["sessionToken"]
      session_index_matches = data[:session_index].to_s.empty? || record["sessionIndex"].to_s.empty? || data[:session_index].to_s == record["sessionIndex"].to_s
      ctx.context.internal_adapter.delete_session(session_token) if session_token && session_index_matches
      ctx.context.internal_adapter.delete_verification_by_identifier(session_identifier)
      ctx.context.internal_adapter.delete_verification_by_identifier("#{SSO_SAML_SESSION_BY_ID_KEY_PREFIX}#{session_token}") if session_token
    rescue
      nil
    end

    def sso_store_saml_logout_request(ctx, provider, request_id, config)
      ttl_ms = (config.dig(:saml, :logout_request_ttl) || SSO_DEFAULT_LOGOUT_REQUEST_TTL_MS).to_i
      ctx.context.internal_adapter.create_verification_value(
        identifier: "#{SSO_SAML_LOGOUT_REQUEST_KEY_PREFIX}#{request_id}",
        value: provider.fetch("providerId"),
        expiresAt: Time.now + (ttl_ms / 1000.0)
      )
    end

    def sso_process_saml_logout_response(ctx, raw_response)
      data = sso_parse_saml_logout_response(raw_response)
      status_code = data[:status_code]
      if status_code && status_code != SSO_SAML_STATUS_SUCCESS
        raise APIError.new("BAD_REQUEST", message: "Logout failed at IdP")
      end

      in_response_to = data[:in_response_to]
      return if in_response_to.to_s.empty?

      ctx.context.internal_adapter.delete_verification_by_identifier("#{SSO_SAML_LOGOUT_REQUEST_KEY_PREFIX}#{in_response_to}")
    end

    def sso_parse_saml_logout_request(raw_request)
      xml = Base64.decode64(raw_request.to_s.gsub(/\s+/, ""))
      {
        name_id: xml[%r{<(?:\w+:)?NameID[^>]*>([^<]+)</(?:\w+:)?NameID>}, 1],
        session_index: xml[%r{<(?:\w+:)?SessionIndex[^>]*>([^<]+)</(?:\w+:)?SessionIndex>}, 1]
      }
    rescue
      {}
    end

    def sso_parse_saml_logout_response(raw_response)
      xml = Base64.decode64(raw_response.to_s.gsub(/\s+/, ""))
      {
        in_response_to: xml[/\bInResponseTo=['"]([^'"]+)['"]/, 1],
        status_code: xml[/<(?:\w+:)?StatusCode\b[^>]*\bValue=['"]([^'"]+)['"]/, 1]
      }
    rescue
      {}
    end

    def sso_safe_slo_redirect_url(ctx, url, provider_id)
      app_origin = ctx.context.base_url
      callback_path = URI.parse("#{ctx.context.base_url}/sso/saml2/sp/slo/#{URI.encode_www_form_component(provider_id)}").path
      value = url.to_s
      return app_origin if value.empty?

      if value.start_with?("/") && !value.start_with?("//")
        parsed = URI.parse(value)
        return app_origin if parsed.path == callback_path
        return value
      end

      return app_origin unless ctx.context.trusted_origin?(value, allow_relative_paths: false)

      parsed = URI.parse(value)
      return app_origin if parsed.path == callback_path

      value
    rescue
      app_origin
    end

    def sso_saml_post_form(action, saml_param, saml_value, relay_state = nil)
      relay_input = relay_state.to_s.empty? ? "" : "<input type=\"hidden\" name=\"RelayState\" value=\"#{CGI.escapeHTML(relay_state.to_s)}\" />"
      html = "<!DOCTYPE html><html><body onload=\"document.forms[0].submit();\"><form method=\"POST\" action=\"#{CGI.escapeHTML(action.to_s)}\"><input type=\"hidden\" name=\"#{CGI.escapeHTML(saml_param.to_s)}\" value=\"#{CGI.escapeHTML(saml_value.to_s)}\" />#{relay_input}<noscript><input type=\"submit\" value=\"Continue\" /></noscript></form></body></html>"
      [200, {"content-type" => "text/html"}, [html]]
    end

    def sso_assign_organization_membership(ctx, provider, user, config)
      organization_id = provider["organizationId"]
      return if organization_id.to_s.empty?
      return if config.dig(:organization_provisioning, :disabled)
      return unless ctx.context.options.plugins.any? { |plugin| plugin.id == "organization" }
      return if ctx.context.adapter.find_one(model: "member", where: [{field: "organizationId", value: organization_id}, {field: "userId", value: user.fetch("id")}])

      role = if config.dig(:organization_provisioning, :get_role).respond_to?(:call)
        config.dig(:organization_provisioning, :get_role).call(user: user, userInfo: {}, provider: provider)
      else
        config.dig(:organization_provisioning, :default_role) || config.dig(:organization_provisioning, :role) || "member"
      end
      ctx.context.adapter.create(model: "member", data: {organizationId: organization_id, userId: user.fetch("id"), role: role, createdAt: Time.now})
    end

    def sso_parse_saml_response(value, config = {}, provider = nil, ctx = nil)
      parser = config.dig(:saml, :parse_response)
      if parser.respond_to?(:call)
        sso_validate_single_saml_assertion!(value) if sso_base64_xml?(value)
        parsed = parser.call(raw_response: value.to_s, provider: provider, context: ctx)
        return normalize_hash(parsed)
      end

      JSON.parse(Base64.decode64(value.to_s), symbolize_names: true)
    rescue APIError
      raise APIError.new("BAD_REQUEST", message: "Invalid SAML response")
    rescue
      raise APIError.new("BAD_REQUEST", message: "Invalid SAML response")
    end

    def sso_validate_single_saml_assertion!(saml_response)
      xml = Base64.decode64(saml_response.to_s)
      raise APIError.new("BAD_REQUEST", message: "Invalid base64-encoded SAML response") unless xml.include?("<")

      assertions = xml.scan(/<(?:\w+:)?Assertion(?:\s|>|\/)/).length
      encrypted_assertions = xml.scan(/<(?:\w+:)?EncryptedAssertion(?:\s|>|\/)/).length
      total = assertions + encrypted_assertions
      raise APIError.new("BAD_REQUEST", message: "SAML response contains no assertions") if total.zero?
      if total > 1
        raise APIError.new("BAD_REQUEST", message: "SAML response contains #{total} assertions, expected exactly 1")
      end

      true
    rescue APIError
      raise
    rescue
      raise APIError.new("BAD_REQUEST", message: "Invalid base64-encoded SAML response")
    end

    def sso_validate_saml_timestamp!(conditions, config = {}, now: Time.now.utc)
      conditions = normalize_hash(conditions || {})
      not_before = conditions[:not_before] || conditions[:notBefore]
      not_on_or_after = conditions[:not_on_or_after] || conditions[:notOnOrAfter]
      if not_before.to_s.empty? && not_on_or_after.to_s.empty?
        raise APIError.new("BAD_REQUEST", message: "SAML assertion missing required timestamp conditions") if config.dig(:saml, :require_timestamps)

        return true
      end

      clock_skew_seconds = ((config.dig(:saml, :clock_skew) || SSO_DEFAULT_CLOCK_SKEW_MS).to_f / 1000.0)
      parsed_not_before = sso_parse_saml_timestamp(not_before, "SAML assertion has invalid NotBefore timestamp") unless not_before.to_s.empty?
      parsed_not_on_or_after = sso_parse_saml_timestamp(not_on_or_after, "SAML assertion has invalid NotOnOrAfter timestamp") unless not_on_or_after.to_s.empty?

      raise APIError.new("BAD_REQUEST", message: "SAML assertion is not yet valid") if parsed_not_before && now < (parsed_not_before - clock_skew_seconds)
      raise APIError.new("BAD_REQUEST", message: "SAML assertion has expired") if parsed_not_on_or_after && now > (parsed_not_on_or_after + clock_skew_seconds)

      true
    end

    def sso_parse_saml_timestamp(value, error_message)
      Time.parse(value.to_s).utc
    rescue
      raise APIError.new("BAD_REQUEST", message: error_message)
    end

    def sso_saml_timestamp_conditions(assertion)
      assertion = normalize_hash(assertion || {})
      conditions = normalize_hash(assertion[:conditions] || {})
      conditions[:not_before] ||= assertion[:not_before] || assertion[:notBefore]
      conditions[:not_on_or_after] ||= assertion[:not_on_or_after] || assertion[:notOnOrAfter]
      conditions
    end

    def sso_base64_xml?(value)
      Base64.decode64(value.to_s).lstrip.start_with?("<")
    rescue
      false
    end

    def sso_validate_saml_algorithms!(xml, options = {})
      on_deprecated = (options[:on_deprecated] || "warn").to_s
      signature_algorithms = xml.to_s.scan(/SignatureMethod[^>]+Algorithm=["']([^"']+)["']/).flatten.map { |algorithm| sso_normalize_saml_signature_algorithm(algorithm) }
      digest_algorithms = xml.to_s.scan(/DigestMethod[^>]+Algorithm=["']([^"']+)["']/).flatten.map { |algorithm| sso_normalize_saml_digest_algorithm(algorithm) }
      key_encryption_algorithms = xml.to_s.scan(/<[^\/>]*EncryptedKey\b[\s\S]*?EncryptionMethod[^>]+Algorithm=["']([^"']+)["']/).flatten
      data_encryption_algorithms = xml.to_s.scan(/<[^\/>]*EncryptedData\b[\s\S]*?EncryptionMethod[^>]+Algorithm=["']([^"']+)["']/).flatten

      sso_validate_saml_algorithm_group!(
        signature_algorithms,
        allowed: options[:allowed_signature_algorithms]&.map { |algorithm| sso_normalize_saml_signature_algorithm(algorithm) },
        secure: SSO_SAML_SECURE_SIGNATURE_ALGORITHMS,
        deprecated: ["http://www.w3.org/2000/09/xmldsig#rsa-sha1"],
        on_deprecated: on_deprecated,
        label: "signature"
      )
      sso_validate_saml_algorithm_group!(
        digest_algorithms,
        allowed: options[:allowed_digest_algorithms]&.map { |algorithm| sso_normalize_saml_digest_algorithm(algorithm) },
        secure: SSO_SAML_SECURE_DIGEST_ALGORITHMS,
        deprecated: ["http://www.w3.org/2000/09/xmldsig#sha1"],
        on_deprecated: on_deprecated,
        label: "digest"
      )
      sso_validate_saml_algorithm_group!(
        key_encryption_algorithms,
        allowed: options[:allowed_key_encryption_algorithms],
        secure: SSO_SAML_SECURE_KEY_ENCRYPTION_ALGORITHMS,
        deprecated: ["http://www.w3.org/2001/04/xmlenc#rsa-1_5"],
        on_deprecated: on_deprecated,
        label: "key encryption"
      )
      sso_validate_saml_algorithm_group!(
        data_encryption_algorithms,
        allowed: options[:allowed_data_encryption_algorithms],
        secure: SSO_SAML_SECURE_DATA_ENCRYPTION_ALGORITHMS,
        deprecated: ["http://www.w3.org/2001/04/xmlenc#tripledes-cbc"],
        on_deprecated: on_deprecated,
        label: "data encryption"
      )

      true
    end

    def sso_normalize_saml_signature_algorithm(algorithm)
      SSO_SAML_SIGNATURE_ALGORITHMS.fetch(algorithm.to_s.downcase, algorithm.to_s)
    end

    def sso_normalize_saml_digest_algorithm(algorithm)
      SSO_SAML_DIGEST_ALGORITHMS.fetch(algorithm.to_s.downcase, algorithm.to_s)
    end

    def sso_validate_saml_algorithm_group!(algorithms, allowed:, secure:, deprecated:, on_deprecated:, label:)
      algorithms.each do |algorithm|
        if allowed
          next if allowed.include?(algorithm)

          raise APIError.new("BAD_REQUEST", message: "SAML #{label} algorithm not in allow-list: #{algorithm}")
        end

        if deprecated.include?(algorithm)
          raise APIError.new("BAD_REQUEST", message: "SAML response uses deprecated #{label} algorithm: #{algorithm}") if on_deprecated == "reject"
          next
        end
        next if secure.include?(algorithm)

        raise APIError.new("BAD_REQUEST", message: "SAML #{label} algorithm not recognized: #{algorithm}")
      end
    end

    def sso_verify_state(value, secret)
      BetterAuth::Crypto.verify_jwt(value.to_s, secret)
    rescue
      nil
    end

    def sso_oidc_authorization_url(provider, ctx, state, plugin_config = {}, body = {})
      config = normalize_hash(provider["oidcConfig"] || {})
      endpoint = config[:authorization_endpoint] || config[:authorization_url]
      raise APIError.new("BAD_REQUEST", message: "Invalid OIDC configuration. Authorization URL not found.") if endpoint.to_s.empty?

      scopes = Array(body[:scopes] || config[:scopes] || config[:scope] || ["openid", "email", "profile", "offline_access"])
      query = {
        client_id: config[:client_id],
        response_type: "code",
        redirect_uri: sso_oidc_redirect_uri(ctx.context, provider.fetch("providerId")),
        scope: scopes.join(" "),
        state: state
      }.compact
      login_hint = body[:login_hint] || body[:email]
      query[:login_hint] = login_hint if login_hint
      code_verifier = sso_decode_state(state, ctx.context.secret)&.fetch("codeVerifier", nil)
      if code_verifier
        query[:code_challenge] = sso_base64_urlsafe(OpenSSL::Digest::SHA256.digest(code_verifier))
        query[:code_challenge_method] = "S256"
      end
      "#{endpoint}?#{URI.encode_www_form(query)}"
    end

    def sso_saml_authorization_url(provider, relay_state, ctx = nil, config = {})
      auth_request_url = config.dig(:saml, :auth_request_url)
      if auth_request_url.respond_to?(:call)
        return auth_request_url.call(provider: provider, relay_state: relay_state, context: ctx)
      end

      config = normalize_hash(provider["samlConfig"] || {})
      query = {
        SAMLRequest: Base64.strict_encode64(JSON.generate({providerId: provider.fetch("providerId")})),
        RelayState: relay_state
      }
      "#{config[:entry_point]}?#{URI.encode_www_form(query)}"
    end

    def sso_store_saml_authn_request(ctx, provider, url, config)
      return if config.dig(:saml, :enable_in_response_to_validation) == false

      request_id = sso_extract_saml_request_id(url)
      return if request_id.to_s.empty?

      ttl_ms = (config.dig(:saml, :request_ttl) || SSO_DEFAULT_AUTHN_REQUEST_TTL_MS).to_i
      now_ms = (Time.now.to_f * 1000).to_i
      expires_at_ms = now_ms + ttl_ms
      record = {
        id: request_id,
        providerId: provider.fetch("providerId"),
        createdAt: now_ms,
        expiresAt: expires_at_ms
      }
      ctx.context.internal_adapter.create_verification_value(
        identifier: "#{SSO_SAML_AUTHN_REQUEST_KEY_PREFIX}#{request_id}",
        value: JSON.generate(record),
        expiresAt: Time.at(expires_at_ms / 1000.0)
      )
    end

    def sso_extract_saml_request_id(url)
      query = URI.decode_www_form(URI.parse(url.to_s).query.to_s).to_h
      encoded = query["SAMLRequest"]
      return nil if encoded.to_s.empty?

      xml = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(Base64.decode64(encoded))
      xml[/\bID=['"]([^'"]+)['"]/, 1]
    rescue
      nil
    end

    def sso_validate_saml_in_response_to(ctx, config, provider, raw_response, state)
      return nil if config.dig(:saml, :enable_in_response_to_validation) == false

      in_response_to = sso_extract_saml_in_response_to(raw_response)
      if in_response_to && !in_response_to.empty?
        identifier = "#{SSO_SAML_AUTHN_REQUEST_KEY_PREFIX}#{in_response_to}"
        verification = ctx.context.internal_adapter.find_verification_value(identifier)
        record = sso_parse_saml_authn_request_record(verification&.fetch("value", nil))
        if !record || record["expiresAt"].to_i < (Time.now.to_f * 1000).to_i
          return sso_redirect(ctx, sso_append_error(state["callbackURL"] || "/", "invalid_saml_response", "Unknown or expired request ID"))
        end

        if record["providerId"] != provider.fetch("providerId")
          ctx.context.internal_adapter.delete_verification_by_identifier(identifier)
          return sso_redirect(ctx, sso_append_error(state["callbackURL"] || "/", "invalid_saml_response", "Provider mismatch"))
        end

        ctx.context.internal_adapter.delete_verification_by_identifier(identifier)
      elsif config.dig(:saml, :allow_idp_initiated) == false
        return sso_redirect(ctx, sso_append_error(state["callbackURL"] || "/", "unsolicited_response", "IdP-initiated SSO not allowed"))
      end

      nil
    end

    def sso_parse_saml_authn_request_record(value)
      JSON.parse(value.to_s)
    rescue
      nil
    end

    def sso_saml_assertion_replay_expires_at(assertion, config = {})
      timestamp = sso_saml_timestamp_conditions(assertion)[:not_on_or_after]
      parsed = Time.parse(timestamp.to_s) if timestamp
      clock_skew_seconds = ((config.dig(:saml, :clock_skew) || SSO_DEFAULT_CLOCK_SKEW_MS).to_f / 1000.0)
      return parsed + clock_skew_seconds if parsed && parsed + clock_skew_seconds > Time.now

      ttl_ms = (config.dig(:saml, :assertion_ttl) || SSO_DEFAULT_ASSERTION_TTL_MS).to_i
      Time.now + (ttl_ms / 1000.0)
    rescue
      Time.now + (SSO_DEFAULT_ASSERTION_TTL_MS / 1000.0)
    end

    def sso_extract_saml_in_response_to(raw_response)
      xml = Base64.decode64(raw_response.to_s.gsub(/\s+/, ""))
      xml[/\bInResponseTo=['"]([^'"]+)['"]/, 1]
    rescue
      nil
    end

    def sso_select_provider(ctx, body, config = {})
      provider_id = body[:provider_id].to_s
      issuer = body[:issuer].to_s
      organization_slug = body[:organization_slug].to_s
      domain = (body[:domain] || body[:email].to_s.split("@").last).to_s.downcase
      if config[:default_sso]
        provider = sso_default_provider(config, provider_id: provider_id, domain: domain)
        return provider if provider
      end

      providers = ctx.context.adapter.find_many(model: "ssoProvider")
      provider = if !provider_id.empty?
        providers.find { |entry| entry["providerId"] == provider_id }
      elsif !issuer.empty?
        providers.find { |entry| entry["issuer"] == issuer }
      elsif !organization_slug.empty?
        organization = ctx.context.adapter.find_one(model: "organization", where: [{field: "slug", value: organization_slug}])
        providers.find { |entry| entry["organizationId"] == organization&.fetch("id", nil) }
      elsif !domain.empty?
        providers.find { |entry| entry["domain"].to_s.downcase == domain } ||
          providers.find { |entry| sso_email_domain_matches?(domain, entry["domain"]) }
      end
      raise APIError.new("NOT_FOUND", message: SSO_ERROR_CODES.fetch("PROVIDER_NOT_FOUND")) unless provider

      provider
    end

    def sso_callback_provider(ctx, config, provider_id)
      if config[:default_sso]
        provider = sso_default_provider(config, provider_id: provider_id.to_s, domain: "")
        return provider if provider
      end

      ctx.context.adapter.find_one(model: "ssoProvider", where: [{field: "providerId", value: provider_id.to_s}])
    end

    def sso_oidc_tokens(ctx, provider, oidc_config, state, plugin_config)
      token_callback = oidc_config[:get_token]
      if token_callback.respond_to?(:call)
        return normalize_hash(token_callback.call(
          code: ctx.query[:code] || ctx.query["code"],
          codeVerifier: state["codeVerifier"],
          redirectURI: sso_oidc_redirect_uri(ctx.context, provider.fetch("providerId")),
          provider: provider,
          context: ctx
        ))
      end

      token_endpoint = oidc_config[:token_endpoint]
      return nil if token_endpoint.to_s.empty?

      sso_exchange_oidc_code(
        token_endpoint: token_endpoint,
        code: ctx.query[:code] || ctx.query["code"],
        code_verifier: state["codeVerifier"],
        redirect_uri: sso_oidc_redirect_uri(ctx.context, provider.fetch("providerId")),
        client_id: oidc_config[:client_id],
        client_secret: oidc_config[:client_secret],
        authentication: oidc_config[:token_endpoint_authentication]
      )
    rescue
      nil
    end

    def sso_exchange_oidc_code(token_endpoint:, code:, code_verifier:, redirect_uri:, client_id:, client_secret:, authentication:)
      uri = URI(token_endpoint.to_s)
      request = Net::HTTP::Post.new(uri)
      form = {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirect_uri,
        client_id: client_id,
        code_verifier: code_verifier
      }.compact
      if authentication.to_s == "client_secret_post"
        form[:client_secret] = client_secret
      elsif client_secret.to_s != ""
        request.basic_auth(client_id.to_s, client_secret.to_s)
      end
      request.set_form_data(form)
      response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |http| http.request(request) }
      return nil unless response.is_a?(Net::HTTPSuccess)

      normalize_hash(JSON.parse(response.body))
    end

    def sso_oidc_user_info(ctx, oidc_config, tokens, plugin_config)
      user_callback = oidc_config[:get_user_info]
      raw = if user_callback.respond_to?(:call)
        user_callback.call(tokens)
      elsif oidc_config[:user_info_endpoint]
        sso_fetch_oidc_user_info(oidc_config[:user_info_endpoint], tokens[:access_token])
      elsif tokens[:id_token]
        return {_sso_error: "jwks_endpoint_not_found"} if oidc_config[:jwks_endpoint].to_s.empty?

        sso_validate_oidc_id_token(
          tokens[:id_token],
          jwks_endpoint: oidc_config[:jwks_endpoint],
          audience: oidc_config[:client_id],
          issuer: oidc_config[:issuer],
          fetch: plugin_config[:oidc_jwks_fetch]
        ) || {_sso_error: "token_not_verified"}
      else
        {}
      end
      raw = normalize_hash(raw || {})
      return raw if raw[:_sso_error]

      mapping = normalize_hash(oidc_config[:mapping] || {})
      extra_fields = normalize_hash(mapping[:extra_fields] || {}).each_with_object({}) do |(target, source), result|
        result[target] = raw[normalize_key(source)] || raw[source.to_s]
      end
      extra_fields.merge(
        id: raw[normalize_key(mapping[:id] || "sub")] || raw[:id],
        email: raw[normalize_key(mapping[:email] || "email")],
        email_verified: plugin_config[:trust_email_verified] ? raw[normalize_key(mapping[:email_verified] || "email_verified")] : false,
        name: raw[normalize_key(mapping[:name] || "name")],
        image: raw[normalize_key(mapping[:image] || "picture")]
      )
    end

    def sso_fetch_oidc_user_info(endpoint, access_token)
      uri = URI(endpoint.to_s)
      request = Net::HTTP::Get.new(uri)
      request["authorization"] = "Bearer #{access_token}"
      response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |http| http.request(request) }
      return {} unless response.is_a?(Net::HTTPSuccess)

      JSON.parse(response.body)
    rescue
      {}
    end

    def sso_validate_oidc_id_token(token, jwks_endpoint:, audience:, issuer:, fetch: nil)
      jwks = sso_fetch_oidc_jwks(jwks_endpoint, fetch: fetch)
      payload, = ::JWT.decode(
        token.to_s,
        nil,
        true,
        algorithms: %w[RS256 RS384 RS512 ES256 ES384 ES512],
        jwks: jwks,
        aud: audience,
        verify_aud: true,
        iss: issuer,
        verify_iss: true
      )
      payload
    rescue
      nil
    end

    def sso_fetch_oidc_jwks(jwks_endpoint, fetch: nil)
      if fetch.respond_to?(:call)
        return normalize_hash(fetch.call(jwks_endpoint))
      end

      uri = URI(jwks_endpoint.to_s)
      response = Net::HTTP.get_response(uri)
      return {} unless response.is_a?(Net::HTTPSuccess)

      normalize_hash(JSON.parse(response.body))
    rescue
      {}
    end

    def sso_decode_jwt_payload(token)
      payload = token.to_s.split(".")[1]
      return {} unless payload

      JSON.parse(Base64.urlsafe_decode64(payload.ljust((payload.length + 3) & ~3, "=")))
    rescue
      {}
    end

    def sso_append_error(url, error, description = nil)
      separator = url.to_s.include?("?") ? "&" : "?"
      query = {error: error, error_description: description}.compact
      "#{url}#{separator}#{URI.encode_www_form(query)}"
    end

    def sso_default_provider(config, provider_id:, domain:)
      Array(config[:default_sso]).each do |raw_provider|
        default_provider = normalize_hash(raw_provider)
        next if !provider_id.empty? && default_provider[:provider_id].to_s != provider_id
        next if provider_id.empty? && default_provider[:domain].to_s.downcase != domain

        oidc_config = default_provider[:oidc_config] ? sso_storage_config(default_provider[:oidc_config]) : nil
        saml_config = default_provider[:saml_config] ? sso_storage_config(default_provider[:saml_config]) : nil
        return {
          "issuer" => default_provider[:issuer] || default_provider.dig(:oidc_config, :issuer) || default_provider.dig(:saml_config, :issuer) || "",
          "providerId" => default_provider.fetch(:provider_id),
          "userId" => "default",
          "domain" => default_provider[:domain],
          "domainVerified" => true,
          "oidcConfig" => oidc_config,
          "samlConfig" => saml_config
        }.compact
      end
      nil
    end

    def sso_oidc_pkce_state(provider)
      return {} unless normalize_hash(provider["oidcConfig"] || {})[:pkce]

      {codeVerifier: BetterAuth::Crypto.random_string(128)}
    end

    def sso_decode_state(state, secret)
      BetterAuth::Crypto.verify_jwt(state.to_s, secret)
    rescue
      nil
    end

    def sso_base64_urlsafe(value)
      Base64.strict_encode64(value).tr("+/", "-_").delete("=")
    end

    def sso_storage_config(config)
      normalize_hash(config || {}).each_with_object({}) do |(key, value), result|
        result[Schema.storage_key(key)] = value unless value.respond_to?(:call)
      end
    end

    def sso_provider_limit(user, config)
      limit = config[:providers_limit]
      limit = 10 if limit.nil?
      limit.respond_to?(:call) ? limit.call(user) : limit
    end

    def sso_validate_url!(value, message)
      uri = URI(value.to_s)
      unless uri.is_a?(URI::HTTP) && !uri.host.to_s.empty?
        raise APIError.new("BAD_REQUEST", message: message)
      end
    rescue URI::InvalidURIError
      raise APIError.new("BAD_REQUEST", message: message)
    end

    def sso_validate_organization_membership!(ctx, user_id, organization_id)
      member = ctx.context.adapter.find_one(
        model: "member",
        where: [{field: "userId", value: user_id}, {field: "organizationId", value: organization_id}]
      )
      raise APIError.new("BAD_REQUEST", message: "You are not a member of the organization") unless member
    end

    def sso_hydrate_oidc_config(issuer, oidc_config, ctx)
      existing = oidc_config.merge(issuer: issuer)
      discovered = sso_discover_oidc_config(
        issuer: issuer,
        existing_config: existing,
        fetch: ctx.context.options.plugins.find { |plugin| plugin.id == "sso" }&.options&.fetch(:oidc_discovery_fetch, nil),
        trusted_origin: ->(url) { ctx.context.trusted_origin?(url, allow_relative_paths: false) }
      )
      existing.merge(discovered)
    end

    def sso_oidc_needs_runtime_discovery?(oidc_config)
      config = normalize_hash(oidc_config || {})
      config[:authorization_endpoint].to_s.empty? ||
        config[:token_endpoint].to_s.empty?
    end

    def sso_ensure_runtime_oidc_provider(ctx, provider, plugin_config, require_jwks: false)
      oidc_config = normalize_hash(provider["oidcConfig"] || {})
      needs_discovery = sso_oidc_needs_runtime_discovery?(oidc_config) || (require_jwks && oidc_config[:jwks_endpoint].to_s.empty?)
      return provider if !needs_discovery

      discovered = sso_discover_oidc_config(
        issuer: provider.fetch("issuer"),
        existing_config: oidc_config.merge(issuer: provider.fetch("issuer")),
        fetch: plugin_config[:oidc_discovery_fetch],
        trusted_origin: ->(url) { ctx.context.trusted_origin?(url, allow_relative_paths: false) }
      )
      provider.merge("oidcConfig" => oidc_config.merge(discovered))
    end

    def sso_oidc_redirect_uri(context, provider_id)
      redirect_uri = context.options.plugins.find { |plugin| plugin.id == "sso" }&.options&.fetch(:redirect_uri, nil)
      if redirect_uri && !redirect_uri.to_s.strip.empty?
        value = redirect_uri.to_s
        return value if URI(value).absolute?

        path = value.start_with?("/") ? value : "/#{value}"
        return "#{context.base_url}#{path}"
      end

      "#{context.base_url}/sso/callback/#{provider_id}"
    rescue URI::InvalidURIError
      "#{context.base_url}/sso/callback/#{provider_id}"
    end

    def sso_email_domain_matches?(email_domain, provider_domain)
      email_domain = email_domain.to_s.strip.downcase
      email_domain = email_domain.split("@", 2).last if email_domain.include?("@")
      return false if email_domain.to_s.empty?

      provider_domain.to_s.split(",").map { |value| value.strip.downcase }.reject(&:empty?).any? do |domain|
        email_domain == domain || email_domain.end_with?(".#{domain}")
      end
    end

    def sso_find_provider!(ctx, provider_id)
      provider = ctx.context.adapter.find_one(model: "ssoProvider", where: [{field: "providerId", value: provider_id.to_s}])
      raise APIError.new("NOT_FOUND", message: SSO_ERROR_CODES.fetch("PROVIDER_NOT_FOUND")) unless provider

      provider
    end

    def sso_provider_access?(provider, user_id, ctx)
      organization_id = provider["organizationId"]
      return provider["userId"] == user_id if organization_id.to_s.empty?
      return provider["userId"] == user_id unless ctx.context.options.plugins.any? { |plugin| plugin.id == "organization" }

      member = ctx.context.adapter.find_one(
        model: "member",
        where: [{field: "userId", value: user_id}, {field: "organizationId", value: organization_id}]
      )
      Array(member&.fetch("role", nil).to_s.split(",")).map(&:strip).any? { |role| %w[owner admin].include?(role) }
    end

    def sso_authorize_domain_verification!(ctx, provider, user_id)
      organization_id = provider["organizationId"]
      is_org_member = true
      if organization_id
        is_org_member = !!ctx.context.adapter.find_one(
          model: "member",
          where: [{field: "userId", value: user_id}, {field: "organizationId", value: organization_id}]
        )
      end
      return if provider["userId"] == user_id && is_org_member

      raise APIError.new("FORBIDDEN", message: "User must be owner of or belong to the SSO provider organization", code: "INSUFICCIENT_ACCESS")
    end

    def sso_domain_verification_identifier(config, provider_id)
      prefix = config.dig(:domain_verification, :token_prefix) || "better-auth-token"
      "_#{prefix}-#{provider_id}"
    end

    def sso_future_time?(value)
      time = value.is_a?(Time) ? value : Time.parse(value.to_s)
      time > Time.now
    rescue
      false
    end

    def sso_hostname_from_domain(domain)
      value = domain.to_s.strip
      return nil if value.empty?

      uri = URI(value.include?("://") ? value : "https://#{value}")
      uri.host
    rescue URI::InvalidURIError
      nil
    end

    def sso_resolve_txt_records(hostname, config)
      resolver = config.dig(:domain_verification, :dns_txt_resolver)
      return Array(resolver.call(hostname)) if resolver.respond_to?(:call)

      Resolv::DNS.open do |dns|
        dns.getresources(hostname, Resolv::DNS::Resource::IN::TXT).map { |record| record.strings }
      end
    rescue
      []
    end

    def sso_sanitize_provider(provider, context)
      data = provider.dup
      oidc_config = normalize_hash(data["oidcConfig"] || {})
      saml_config = normalize_hash(data["samlConfig"] || {})
      data["type"] = saml_config.empty? ? "oidc" : "saml"
      data["organizationId"] ||= nil
      data["domainVerified"] = !!data["domainVerified"]
      data.delete("domainVerified") unless sso_context_domain_verification_enabled?(context)
      data["oidcConfig"] = oidc_config.empty? ? nil : sso_sanitize_oidc_config(oidc_config)
      data["samlConfig"] = saml_config.empty? ? nil : sso_sanitize_saml_config(saml_config)
      data["spMetadataUrl"] = "#{context.base_url}/sso/saml2/sp/metadata?providerId=#{URI.encode_www_form_component(data.fetch("providerId"))}"
      data.compact
    end

    def sso_context_domain_verification_enabled?(context)
      context.options.plugins.any? do |plugin|
        plugin.id == "sso" && plugin.options.dig(:domain_verification, :enabled)
      end
    end

    def sso_sanitize_config(config)
      data = normalize_hash(config || {})
      data.delete(:client_secret)
      data.each_with_object({}) { |(key, value), result| result[Schema.storage_key(key)] = value unless value.respond_to?(:call) }
    end

    def sso_sanitize_oidc_config(config)
      {
        "clientIdLastFour" => sso_mask_client_id(config[:client_id]),
        "authorizationEndpoint" => config[:authorization_endpoint],
        "tokenEndpoint" => config[:token_endpoint],
        "userInfoEndpoint" => config[:user_info_endpoint],
        "jwksEndpoint" => config[:jwks_endpoint],
        "scopes" => config[:scopes],
        "tokenEndpointAuthentication" => config[:token_endpoint_authentication],
        "pkce" => config[:pkce],
        "discoveryEndpoint" => config[:discovery_endpoint]
      }.compact
    end

    def sso_sanitize_saml_config(config)
      {
        "entryPoint" => config[:entry_point],
        "callbackUrl" => config[:callback_url],
        "audience" => config[:audience],
        "wantAssertionsSigned" => config[:want_assertions_signed],
        "authnRequestsSigned" => config[:authn_requests_signed],
        "identifierFormat" => config[:identifier_format],
        "signatureAlgorithm" => config[:signature_algorithm],
        "digestAlgorithm" => config[:digest_algorithm],
        "certificate" => sso_parse_certificate(config[:cert])
      }.compact
    end

    def sso_mask_client_id(client_id)
      value = client_id.to_s
      return "****" if value.length <= 4

      "****#{value[-4, 4]}"
    end

    def sso_parse_certificate(cert)
      OpenSSL::X509::Certificate.new(cert.to_s)
      {subject: cert.to_s.lines.first.to_s.strip}
    rescue
      {error: "Failed to parse certificate"}
    end

    def sso_fetch(data, key)
      return nil unless data.respond_to?(:[])

      compact = key.to_s.delete("_").downcase
      direct = data[key] ||
        data[key.to_s] ||
        data[Schema.storage_key(key)] ||
        data[Schema.storage_key(key).to_sym] ||
        data[compact] ||
        data[compact.to_sym]
      return direct unless direct.nil?

      data.each do |candidate, value|
        normalized = candidate.to_s.delete("_").downcase
        return value if normalized == compact
      end
      nil
    end

    def sso_redirect(ctx, location)
      [302, ctx.response_headers.merge("location" => location), [""]]
    end
  end
end
