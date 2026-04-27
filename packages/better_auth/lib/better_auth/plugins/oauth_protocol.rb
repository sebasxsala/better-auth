# frozen_string_literal: true

require "base64"
require "openssl"
require "uri"

module BetterAuth
  module Plugins
    module OAuthProtocol
      AUTH_CODE_GRANT = "authorization_code"
      REFRESH_GRANT = "refresh_token"
      CLIENT_CREDENTIALS_GRANT = "client_credentials"
      DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

      module_function

      def parse_scopes(value)
        case value
        when Array
          value.map(&:to_s).reject(&:empty?)
        else
          value.to_s.split(/\s+/).reject(&:empty?)
        end
      end

      def scope_string(value)
        parse_scopes(value).join(" ")
      end

      def issuer(ctx)
        ctx.context.options.base_url.to_s.empty? ? origin_for(ctx.context.base_url) : ctx.context.options.base_url
      end

      def endpoint_base(ctx)
        ctx.context.base_url
      end

      def origin_for(url)
        uri = URI.parse(url.to_s)
        port = uri.port
        default_port = (uri.scheme == "http" && port == 80) || (uri.scheme == "https" && port == 443)
        default_port ? "#{uri.scheme}://#{uri.host}" : "#{uri.scheme}://#{uri.host}:#{port}"
      end

      def redirect_uri_with_params(uri, params)
        parsed = URI.parse(uri.to_s)
        existing = URI.decode_www_form(parsed.query.to_s)
        params.each { |key, value| existing << [key.to_s, value.to_s] unless value.nil? }
        parsed.query = URI.encode_www_form(existing)
        parsed.to_s
      end

      def validate_redirect_uri!(client, redirect_uri)
        redirects = client_redirect_uris(client)
        return if redirects.include?(redirect_uri.to_s)

        raise APIError.new("BAD_REQUEST", message: "invalid redirect_uri")
      end

      def client_redirect_uris(client)
        value = client["redirectUris"] || client["redirectUrls"] || client[:redirect_uris] || client[:redirectUrls]
        return value if value.is_a?(Array)

        value.to_s.split(",").map(&:strip).reject(&:empty?)
      end

      def client_logout_redirect_uris(client)
        value = client["postLogoutRedirectUris"] || client[:post_logout_redirect_uris]
        return value if value.is_a?(Array)

        value.to_s.split(",").map(&:strip).reject(&:empty?)
      end

      def create_client(ctx, model:, body:, owner_session: nil, default_auth_method: "client_secret_basic", store_client_secret: "plain")
        body = stringify_keys(body || {})
        auth_method = body["token_endpoint_auth_method"] || default_auth_method
        public_client = auth_method == "none"
        client_id = body["client_id"] || Crypto.random_string(32)
        client_secret = public_client ? nil : (body["client_secret"] || Crypto.random_string(32))
        redirects = Array(body["redirect_uris"]).map(&:to_s)
        raise APIError.new("BAD_REQUEST", message: "redirect_uris is required") if redirects.empty?

        scopes = parse_scopes(body["scope"] || body["scopes"])
        data = {
          "clientId" => client_id,
          "clientSecret" => client_secret ? store_client_secret_value(ctx, client_secret, store_client_secret) : nil,
          "type" => public_client ? "public" : "web",
          "name" => body["client_name"] || body["name"] || "OAuth Client",
          "icon" => body["logo_uri"],
          "uri" => body["client_uri"],
          "redirectUris" => redirects,
          "redirectUrls" => redirects.join(","),
          "postLogoutRedirectUris" => Array(body["post_logout_redirect_uris"]).map(&:to_s),
          "tokenEndpointAuthMethod" => auth_method,
          "grantTypes" => Array(body["grant_types"] || [AUTH_CODE_GRANT]),
          "responseTypes" => Array(body["response_types"] || ["code"]),
          "scopes" => scopes,
          "skipConsent" => body["skip_consent"] || body["skipConsent"] || false,
          "metadata" => body["metadata"] || {},
          "disabled" => false
        }
        data["userId"] = owner_session[:user]["id"] if owner_session
        created = ctx.context.adapter.create(model: model, data: data)
        client_response(created).merge(
          client_secret: client_secret,
          client_id_issued_at: Time.now.to_i,
          client_secret_expires_at: 0
        ).compact
      end

      def client_response(client, include_secret: true)
        data = stringify_keys(client || {})
        response = {
          client_id: data["clientId"],
          client_name: data["name"],
          client_uri: data["uri"],
          logo_uri: data["icon"],
          redirect_uris: client_redirect_uris(data),
          post_logout_redirect_uris: client_logout_redirect_uris(data),
          token_endpoint_auth_method: data["tokenEndpointAuthMethod"] || "client_secret_basic",
          grant_types: data["grantTypes"] || [],
          response_types: data["responseTypes"] || [],
          skip_consent: !!data["skipConsent"],
          scope: scope_string(data["scopes"]),
          metadata: data["metadata"]
        }
        response[:client_secret] = data["clientSecret"] if include_secret && data["clientSecret"]
        response
      end

      def find_client(ctx, model, client_id)
        ctx.context.adapter.find_one(model: model, where: [{field: "clientId", value: client_id.to_s}])
      end

      def authenticate_client!(ctx, model, store_client_secret: "plain")
        body = stringify_keys(ctx.body || {})
        client_id = body["client_id"]
        client_secret = body["client_secret"]

        authorization = ctx.headers["authorization"]
        if authorization.to_s.start_with?("Basic ") && client_id.to_s.empty?
          decoded = Base64.decode64(authorization.delete_prefix("Basic "))
          client_id, client_secret = decoded.split(":", 2)
        end

        client = find_client(ctx, model, client_id)
        raise APIError.new("UNAUTHORIZED", message: "invalid_client") unless client

        method = stringify_keys(client)["tokenEndpointAuthMethod"] || "client_secret_basic"
        if method != "none" && !verify_client_secret(ctx, stringify_keys(client)["clientSecret"], client_secret, store_client_secret)
          raise APIError.new("UNAUTHORIZED", message: "invalid_client")
        end

        client
      rescue ArgumentError
        raise APIError.new("UNAUTHORIZED", message: "invalid_client")
      end

      def store_code(store, code:, client_id:, redirect_uri:, session:, scopes:, code_challenge: nil, code_challenge_method: nil)
        store[:codes][code] = {
          client_id: client_id,
          redirect_uri: redirect_uri,
          session: session,
          scopes: parse_scopes(scopes),
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method,
          expires_at: Time.now + 600
        }
      end

      def consume_code!(store, code, client_id:, redirect_uri:, code_verifier: nil)
        data = store[:codes].delete(code.to_s)
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless data
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") if data[:expires_at] <= Time.now
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless data[:client_id] == client_id.to_s
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless data[:redirect_uri] == redirect_uri.to_s
        verify_pkce!(data, code_verifier) if data[:code_challenge]

        data
      end

      def verify_pkce!(code_data, verifier)
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") if verifier.to_s.empty?

        challenge = if code_data[:code_challenge_method].to_s == "S256"
          Base64.urlsafe_encode64(OpenSSL::Digest.digest("SHA256", verifier.to_s), padding: false)
        else
          verifier.to_s
        end
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless challenge == code_data[:code_challenge]
      end

      def issue_tokens(ctx, store, model:, client:, session:, scopes:, include_refresh: false, issuer: nil, jwt_audience: nil, access_token_expires_in: 3600, id_token_signer: nil)
        data = stringify_keys(session || {})
        user = stringify_keys(data["user"] || data[:user] || {})
        session_data = stringify_keys(data["session"] || data[:session] || {})
        client_data = stringify_keys(client)
        access_token = "ba_at_#{Crypto.random_string(32)}"
        refresh_token = include_refresh ? "ba_rt_#{Crypto.random_string(32)}" : nil
        scope = scope_string(scopes)
        expires_at = Time.now + access_token_expires_in.to_i
        record = {
          "accessToken" => access_token,
          "token" => access_token,
          "refreshToken" => refresh_token,
          "accessTokenExpiresAt" => expires_at,
          "expiresAt" => expires_at,
          "clientId" => client_data["clientId"],
          "userId" => user["id"],
          "sessionId" => session_data["id"],
          "scope" => scope,
          "scopes" => parse_scopes(scope),
          "revoked" => nil
        }
        ctx.context.adapter.create(model: model, data: record)
        stored_record = record.merge("user" => user, "session" => session_data, "client" => client_data)
        store[:tokens][access_token] = stored_record
        store[:refresh_tokens][refresh_token] = stored_record if refresh_token

        response = {
          access_token: access_token,
          token_type: "Bearer",
          expires_in: access_token_expires_in.to_i,
          scope: scope
        }
        response[:refresh_token] = refresh_token if refresh_token
        response[:id_token] = id_token(user, client_data["clientId"], issuer || issuer(ctx), jwt_audience || client_data["clientId"], ctx: ctx, signer: id_token_signer) if parse_scopes(scope).include?("openid")
        response
      end

      def refresh_tokens(ctx, store, model:, client:, refresh_token:, scopes: nil, issuer: nil, access_token_expires_in: 3600, id_token_signer: nil)
        data = store[:refresh_tokens].delete(refresh_token.to_s)
        raise APIError.new("BAD_REQUEST", message: "invalid_grant") unless data
        requested = scopes ? parse_scopes(scopes) : data["scopes"]
        unless requested.all? { |scope| data["scopes"].include?(scope) }
          raise APIError.new("BAD_REQUEST", message: "invalid_scope")
        end

        issue_tokens(
          ctx,
          store,
          model: model,
          client: client,
          session: {"user" => data["user"], "session" => data["session"]},
          scopes: requested,
          include_refresh: true,
          issuer: issuer,
          access_token_expires_in: access_token_expires_in,
          id_token_signer: id_token_signer
        )
      end

      def token_record(store, token)
        data = store[:tokens][token.to_s]
        return nil unless data
        return nil if data["revoked"]
        return nil if data["expiresAt"] && data["expiresAt"] <= Time.now

        data
      end

      def userinfo(store, authorization, additional_claim: nil)
        token = authorization.to_s.delete_prefix("Bearer ").strip
        record = token_record(store, token)
        raise APIError.new("UNAUTHORIZED", message: "invalid_token") unless record
        user = stringify_keys(record["user"])
        scopes = parse_scopes(record["scope"] || record["scopes"])
        response = {sub: user["id"]}
        response[:name] = user["name"] if scopes.include?("profile")
        if scopes.include?("email")
          response[:email] = user["email"]
          response[:email_verified] = !!user["emailVerified"]
        end
        if additional_claim.respond_to?(:call)
          extra = additional_claim.call(user, scopes, stringify_keys(record["client"] || {}))
          response.merge!(extra) if extra.is_a?(Hash)
        end
        response
      end

      def id_token(user, client_id, issuer_value, audience, ctx: nil, signer: nil)
        payload = {
          sub: user["id"],
          iss: issuer_value,
          aud: audience || client_id,
          email: user["email"],
          email_verified: !!user["emailVerified"],
          name: user["name"]
        }
        return signer.call(ctx, payload) if signer.respond_to?(:call)

        Crypto.sign_jwt(
          payload,
          client_id.to_s.empty? ? "better-auth" : client_id.to_s,
          expires_in: 3600
        )
      end

      def store_client_secret_value(ctx, secret, mode)
        mode = normalize_secret_storage_mode(mode)
        return Crypto.sha256(secret, encoding: :base64url) if mode == "hashed"
        return Crypto.symmetric_encrypt(key: ctx.context.secret, data: secret) if mode == "encrypted"

        if mode.is_a?(Hash)
          return mode[:hash].call(secret) if mode[:hash].respond_to?(:call)
          return mode[:encrypt].call(secret) if mode[:encrypt].respond_to?(:call)
        end

        secret
      end

      def verify_client_secret(ctx, stored_secret, provided_secret, mode)
        mode = normalize_secret_storage_mode(mode)
        return Crypto.constant_time_compare(Crypto.sha256(provided_secret, encoding: :base64url), stored_secret.to_s) if mode == "hashed"
        return Crypto.symmetric_decrypt(key: ctx.context.secret, data: stored_secret) == provided_secret.to_s if mode == "encrypted"

        if mode.is_a?(Hash)
          return mode[:hash].call(provided_secret).to_s == stored_secret.to_s if mode[:hash].respond_to?(:call)
          return mode[:decrypt].call(stored_secret).to_s == provided_secret.to_s if mode[:decrypt].respond_to?(:call)
        end

        Crypto.constant_time_compare(stored_secret.to_s, provided_secret.to_s)
      end

      def normalize_secret_storage_mode(mode)
        return stringify_keys(mode).transform_keys(&:to_sym) if mode.is_a?(Hash)

        mode.to_s
      end

      def stores
        {
          codes: {},
          tokens: {},
          refresh_tokens: {},
          consents: {}
        }
      end

      def stringify_keys(value)
        return value.each_with_object({}) { |(key, object_value), result| result[key.to_s] = stringify_keys(object_value) } if value.is_a?(Hash)
        return value.map { |entry| stringify_keys(entry) } if value.is_a?(Array)

        value
      end
    end
  end
end
