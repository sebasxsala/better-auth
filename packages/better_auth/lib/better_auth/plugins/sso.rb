# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "openssl"
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
          sign_in_sso: sso_sign_in_endpoint(config),
          callback_sso: sso_oidc_callback_endpoint,
          callback_sso_saml: sso_saml_callback_endpoint(config),
          acs_endpoint: sso_saml_acs_endpoint(config),
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
        URI.join("#{issuer_uri.scheme}://#{issuer_uri.host}", value.to_s).to_s
      end
      if trusted_origin && !trusted_origin.call(normalized)
        raise APIError.new("BAD_REQUEST", message: "OIDC discovery endpoint is not trusted")
      end

      normalized
    rescue URI::InvalidURIError
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
          .select { |provider| sso_provider_access?(provider, session.fetch(:user).fetch("id"), ctx) }
          .map { |provider| sso_sanitize_provider(provider, ctx.context) }
        ctx.json({providers: providers})
      end
    end

    def sso_get_provider_endpoint
      Endpoint.new(path: "/sso/providers/:providerId", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        provider = sso_find_provider!(ctx, sso_fetch(ctx.params, :provider_id))
        raise APIError.new("FORBIDDEN", message: "Access denied") unless sso_provider_access?(provider, session.fetch(:user).fetch("id"), ctx)

        ctx.json(sso_sanitize_provider(provider, ctx.context))
      end
    end

    def sso_update_provider_endpoint
      Endpoint.new(path: "/sso/providers/:providerId", method: "PATCH") do |ctx|
        session = Routes.current_session(ctx)
        provider = sso_find_provider!(ctx, sso_fetch(ctx.params, :provider_id))
        raise APIError.new("FORBIDDEN", message: "Access denied") unless sso_provider_access?(provider, session.fetch(:user).fetch("id"), ctx)

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
        raise APIError.new("FORBIDDEN", message: "Access denied") unless sso_provider_access?(provider, session.fetch(:user).fetch("id"), ctx)

        ctx.context.adapter.delete(model: "ssoProvider", where: [{field: "id", value: provider.fetch("id")}])
        ctx.json({success: true})
      end
    end

    def sso_sign_in_endpoint(config = {})
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
          url = sso_saml_authorization_url(provider, relay_state, ctx, config)
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

    def sso_handle_saml_response(ctx, config = {})
      provider = sso_find_provider!(ctx, sso_fetch(ctx.params, :provider_id))
      relay_state = sso_fetch(ctx.body, :relay_state) || sso_fetch(ctx.query, :relay_state)
      state = sso_verify_state(relay_state, ctx.context.secret) || {}
      assertion = sso_parse_saml_response(sso_fetch(ctx.body, :saml_response), config, provider, ctx)
      sso_validate_saml_response!(config, assertion, provider, ctx)
      assertion_id = assertion[:id] || assertion["id"] || assertion[:email]
      replay_key = "sso-saml-assertion:#{provider.fetch("providerId")}:#{assertion_id}"
      if ctx.context.internal_adapter.find_verification_value(replay_key)
        raise APIError.new("BAD_REQUEST", message: SSO_ERROR_CODES.fetch("SAML_RESPONSE_REPLAYED"))
      end
      ctx.context.internal_adapter.create_verification_value(identifier: replay_key, value: "used", expiresAt: Time.now + 300)

      user = sso_find_or_create_user(ctx, provider, assertion, config)
      session = ctx.context.internal_adapter.create_session(user.fetch("id"))
      Cookies.set_session_cookie(ctx, {session: session, user: user})
      callback_url = state["callbackURL"] || "/"
      callback_url = "/" unless ctx.context.trusted_origin?(callback_url, allow_relative_paths: true)
      sso_redirect(ctx, callback_url)
    end

    def sso_find_or_create_user(ctx, provider, user_info, config = {})
      user_info = normalize_hash(user_info)
      email = user_info[:email].to_s.downcase
      found = ctx.context.internal_adapter.find_user_by_email(email)
      user = if found
        found[:user]
      else
        created = ctx.context.internal_adapter.create_user(
          email: email,
          name: user_info[:name] || email,
          emailVerified: user_info.key?(:email_verified) ? user_info[:email_verified] : true,
          image: user_info[:image]
        )
        ctx.context.internal_adapter.create_account(
          accountId: (user_info[:id] || created.fetch("id")).to_s,
          providerId: "sso:#{provider.fetch("providerId")}",
          userId: created.fetch("id")
        )
        created
      end
      sso_assign_organization_membership(ctx, provider, user, config)
      user
    end

    def sso_validate_saml_response!(config, assertion, provider, ctx)
      validator = config.dig(:saml, :validate_response)
      return unless validator.respond_to?(:call)
      return if validator.call(response: assertion, provider: provider, context: ctx)

      raise APIError.new("BAD_REQUEST", message: "Invalid SAML response")
    end

    def sso_assign_organization_membership(ctx, provider, user, config)
      organization_id = provider["organizationId"]
      return if organization_id.to_s.empty?
      return unless provider["domainVerified"]
      return unless sso_email_domain_matches?(user["email"].to_s.split("@").last.to_s.downcase, provider["domain"])
      return unless ctx.context.options.plugins.any? { |plugin| plugin.id == "organization" }
      return if ctx.context.adapter.find_one(model: "member", where: [{field: "organizationId", value: organization_id}, {field: "userId", value: user.fetch("id")}])

      role = config.dig(:organization_provisioning, :role) || "member"
      ctx.context.adapter.create(model: "member", data: {organizationId: organization_id, userId: user.fetch("id"), role: role, createdAt: Time.now})
    end

    def sso_parse_saml_response(value, config = {}, provider = nil, ctx = nil)
      parser = config.dig(:saml, :parse_response)
      if parser.respond_to?(:call)
        parsed = parser.call(raw_response: value.to_s, provider: provider, context: ctx)
        return normalize_hash(parsed)
      end

      JSON.parse(Base64.decode64(value.to_s), symbolize_names: true)
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

    def sso_validate_saml_algorithms!(xml, options = {})
      on_deprecated = (options[:on_deprecated] || "warn").to_s
      signature_algorithms = xml.to_s.scan(/SignatureMethod[^>]+Algorithm=["']([^"']+)["']/).flatten
      signature_algorithms.each do |algorithm|
        if algorithm == "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
          raise APIError.new("BAD_REQUEST", message: "SAML response uses deprecated signature algorithm: #{algorithm}") if on_deprecated == "reject"
          next
        end
        next if %w[
          http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
          http://www.w3.org/2001/04/xmldsig-more#rsa-sha384
          http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
          http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256
          http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384
          http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512
        ].include?(algorithm)

        raise APIError.new("BAD_REQUEST", message: "SAML signature algorithm not recognized: #{algorithm}")
      end

      true
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

    def sso_provider_access?(provider, user_id, ctx)
      organization_id = provider["organizationId"]
      return provider["userId"] == user_id if organization_id.to_s.empty?
      return false unless ctx.context.options.plugins.any? { |plugin| plugin.id == "organization" }

      member = ctx.context.adapter.find_one(
        model: "member",
        where: [{field: "userId", value: user_id}, {field: "organizationId", value: organization_id}]
      )
      Array(member&.fetch("role", nil).to_s.split(",")).map(&:strip).any? { |role| %w[owner admin].include?(role) }
    end

    def sso_sanitize_provider(provider, context)
      data = provider.dup
      oidc_config = normalize_hash(data["oidcConfig"] || {})
      saml_config = normalize_hash(data["samlConfig"] || {})
      data["type"] = saml_config.empty? ? "oidc" : "saml"
      data["organizationId"] ||= nil
      data["domainVerified"] = !!data["domainVerified"]
      data["oidcConfig"] = oidc_config.empty? ? nil : sso_sanitize_oidc_config(oidc_config)
      data["samlConfig"] = saml_config.empty? ? nil : sso_sanitize_saml_config(saml_config)
      data["spMetadataUrl"] = "#{context.base_url}/sso/saml2/sp/metadata?providerId=#{URI.encode_www_form_component(data.fetch("providerId"))}"
      data.compact
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
