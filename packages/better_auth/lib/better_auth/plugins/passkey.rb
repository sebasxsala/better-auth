# frozen_string_literal: true

require "base64"
require "uri"
require "webauthn"

module BetterAuth
  module Plugins
    module_function

    PASSKEY_ERROR_CODES = {
      "CHALLENGE_NOT_FOUND" => "Challenge not found",
      "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY" => "You are not allowed to register this passkey",
      "FAILED_TO_VERIFY_REGISTRATION" => "Failed to verify registration",
      "PASSKEY_NOT_FOUND" => "Passkey not found",
      "AUTHENTICATION_FAILED" => "Authentication failed",
      "UNABLE_TO_CREATE_SESSION" => "Unable to create session",
      "FAILED_TO_UPDATE_PASSKEY" => "Failed to update passkey"
    }.freeze

    PASSKEY_CHALLENGE_MAX_AGE = 60 * 5

    def passkey(options = {})
      config = {
        origin: nil,
        advanced: {
          web_authn_challenge_cookie: "better-auth-passkey"
        }
      }.merge(normalize_hash(options))
      config[:advanced] = {
        web_authn_challenge_cookie: "better-auth-passkey"
      }.merge(config[:advanced] || {})

      Plugin.new(
        id: "passkey",
        schema: passkey_schema(config[:schema]),
        endpoints: {
          generate_passkey_registration_options: generate_passkey_registration_options_endpoint(config),
          generate_passkey_authentication_options: generate_passkey_authentication_options_endpoint(config),
          verify_passkey_registration: verify_passkey_registration_endpoint(config),
          verify_passkey_authentication: verify_passkey_authentication_endpoint(config),
          list_passkeys: list_passkeys_endpoint,
          delete_passkey: delete_passkey_endpoint,
          update_passkey: update_passkey_endpoint
        },
        error_codes: PASSKEY_ERROR_CODES,
        options: config
      )
    end

    def generate_passkey_registration_options_endpoint(config)
      Endpoint.new(path: "/passkey/generate-register-options", method: "GET") do |ctx|
        session = Routes.current_session(ctx, sensitive: true)
        user = session.fetch(:user)
        passkey_configure_webauthn(config, ctx)
        existing = ctx.context.adapter.find_many(model: "passkey", where: [{field: "userId", value: user.fetch("id")}])
        query = normalize_hash(ctx.query)
        options = WebAuthn::Credential.options_for_create(
          user: {
            id: Crypto.random_string(32).downcase,
            name: query[:name].to_s.empty? ? (user["email"] || user["id"]) : query[:name].to_s,
            display_name: user["email"] || user["id"]
          },
          exclude: existing.map { |passkey| passkey_credential_id(passkey) },
          authenticator_selection: passkey_authenticator_selection(config, query)
        )
        passkey_store_challenge(ctx, config, options.challenge, user.fetch("id"))
        ctx.json(options.as_json.merge(excludeCredentials: existing.map { |passkey| passkey_credential_descriptor(passkey) }))
      end
    end

    def generate_passkey_authentication_options_endpoint(config)
      Endpoint.new(path: "/passkey/generate-authenticate-options", method: "GET") do |ctx|
        session = Routes.current_session(ctx, allow_nil: true)
        passkey_configure_webauthn(config, ctx)
        passkeys = if session
          ctx.context.adapter.find_many(model: "passkey", where: [{field: "userId", value: session.fetch(:user).fetch("id")}])
        else
          []
        end
        options = WebAuthn::Credential.options_for_get(allow: passkeys.map { |passkey| passkey_credential_id(passkey) })
        passkey_store_challenge(ctx, config, options.challenge, session ? session.fetch(:user).fetch("id") : "")
        payload = options.as_json.merge(userVerification: "preferred")
        payload[:allowCredentials] = passkeys.map { |passkey| passkey_credential_descriptor(passkey) } if passkeys.any?
        ctx.json(payload)
      end
    end

    def verify_passkey_registration_endpoint(config)
      Endpoint.new(path: "/passkey/verify-registration", method: "POST") do |ctx|
        session = Routes.current_session(ctx, sensitive: true)
        origin = passkey_origin(config, ctx)
        raise APIError.new("BAD_REQUEST", message: "origin missing") if origin.to_s.empty?

        verification_token = passkey_challenge_token(ctx, config)
        raise APIError.new("BAD_REQUEST", message: PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND")) unless verification_token

        challenge = passkey_find_challenge(ctx, verification_token)
        unless challenge
          raise APIError.new("BAD_REQUEST", message: PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND"))
        end
        if challenge.fetch("userData").fetch("id") != session.fetch(:user).fetch("id")
          raise APIError.new("UNAUTHORIZED", message: PASSKEY_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"))
        end

        response = passkey_webauthn_response(normalize_hash(ctx.body)[:response])
        passkey_configure_webauthn(config, ctx, origin: origin)
        credential = WebAuthn::Credential.from_create(response)
        credential.verify(challenge.fetch("expectedChallenge"), user_verification: false)
        authenticator_data = passkey_authenticator_data(credential)
        body = normalize_hash(ctx.body)
        data = ctx.context.adapter.create(
          model: "passkey",
          data: {
            name: body[:name],
            userId: challenge.fetch("userData").fetch("id"),
            credentialID: credential.id,
            publicKey: Base64.strict_encode64(credential.public_key),
            counter: credential.sign_count,
            deviceType: authenticator_data&.credential_backup_eligible? ? "multiDevice" : "singleDevice",
            backedUp: authenticator_data&.credential_backed_up? || false,
            transports: Array(passkey_attestation_response(credential)&.transports).join(","),
            createdAt: Time.now,
            aaguid: passkey_attestation_response(credential)&.aaguid
          }
        )
        ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
        ctx.json(passkey_wire(data))
      rescue WebAuthn::Error => error
        ctx.context.logger&.error("Failed to verify registration", error)
        raise APIError.new("INTERNAL_SERVER_ERROR", message: PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"))
      end
    end

    def verify_passkey_authentication_endpoint(config)
      Endpoint.new(path: "/passkey/verify-authentication", method: "POST") do |ctx|
        origin = passkey_origin(config, ctx)
        raise APIError.new("BAD_REQUEST", message: "origin missing") if origin.to_s.empty?

        verification_token = passkey_challenge_token(ctx, config)
        raise APIError.new("BAD_REQUEST", message: PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND")) unless verification_token

        challenge = passkey_find_challenge(ctx, verification_token)
        raise APIError.new("BAD_REQUEST", message: PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND")) unless challenge

        response = passkey_webauthn_response(normalize_hash(ctx.body)[:response])
        credential_id = response.fetch("id")
        passkey = ctx.context.adapter.find_one(model: "passkey", where: [{field: "credentialID", value: credential_id}])
        raise APIError.new("UNAUTHORIZED", message: PASSKEY_ERROR_CODES.fetch("PASSKEY_NOT_FOUND")) unless passkey

        passkey_configure_webauthn(config, ctx, origin: origin)
        credential = WebAuthn::Credential.from_get(response)
        credential.verify(
          challenge.fetch("expectedChallenge"),
          public_key: Base64.strict_decode64(passkey.fetch("publicKey")),
          sign_count: passkey.fetch("counter").to_i,
          user_verification: false
        )
        ctx.context.adapter.update(
          model: "passkey",
          where: [{field: "id", value: passkey.fetch("id")}],
          update: {counter: credential.sign_count}
        )
        session = ctx.context.internal_adapter.create_session(passkey.fetch("userId"))
        raise APIError.new("INTERNAL_SERVER_ERROR", message: PASSKEY_ERROR_CODES.fetch("UNABLE_TO_CREATE_SESSION")) unless session

        user = ctx.context.internal_adapter.find_user_by_id(passkey.fetch("userId"))
        raise APIError.new("INTERNAL_SERVER_ERROR", message: "User not found") unless user

        Cookies.set_session_cookie(ctx, {session: session, user: user})
        ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
        ctx.json({session: session})
      rescue WebAuthn::Error, ArgumentError => error
        ctx.context.logger&.error("Failed to verify authentication", error)
        raise APIError.new("BAD_REQUEST", message: PASSKEY_ERROR_CODES.fetch("AUTHENTICATION_FAILED"))
      end
    end

    def list_passkeys_endpoint
      Endpoint.new(path: "/passkey/list-user-passkeys", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        passkeys = ctx.context.adapter.find_many(model: "passkey", where: [{field: "userId", value: session.fetch(:user).fetch("id")}])
        ctx.json(passkeys.map { |passkey| passkey_wire(passkey) })
      end
    end

    def delete_passkey_endpoint
      Endpoint.new(path: "/passkey/delete-passkey", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        passkey = ctx.context.adapter.find_one(model: "passkey", where: [{field: "id", value: body[:id]}])
        raise APIError.new("NOT_FOUND", message: PASSKEY_ERROR_CODES.fetch("PASSKEY_NOT_FOUND")) unless passkey
        raise APIError.new("UNAUTHORIZED") unless passkey.fetch("userId") == session.fetch(:user).fetch("id")

        ctx.context.adapter.delete(model: "passkey", where: [{field: "id", value: passkey.fetch("id")}])
        ctx.json({status: true})
      end
    end

    def update_passkey_endpoint
      Endpoint.new(path: "/passkey/update-passkey", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        passkey = ctx.context.adapter.find_one(model: "passkey", where: [{field: "id", value: body[:id]}])
        raise APIError.new("NOT_FOUND", message: PASSKEY_ERROR_CODES.fetch("PASSKEY_NOT_FOUND")) unless passkey
        if passkey.fetch("userId") != session.fetch(:user).fetch("id")
          raise APIError.new("UNAUTHORIZED", message: PASSKEY_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"))
        end

        updated = ctx.context.adapter.update(
          model: "passkey",
          where: [{field: "id", value: body[:id]}],
          update: {name: body[:name].to_s}
        )
        raise APIError.new("INTERNAL_SERVER_ERROR", message: PASSKEY_ERROR_CODES.fetch("FAILED_TO_UPDATE_PASSKEY")) unless updated

        ctx.json({passkey: passkey_wire(updated)})
      end
    end

    def passkey_schema(custom_schema = nil)
      base = {
        passkey: {
          model_name: "passkeys",
          fields: {
            name: {type: "string", required: false},
            publicKey: {type: "string", required: true},
            userId: {type: "string", references: {model: "user", field: "id"}, required: true, index: true},
            credentialID: {type: "string", required: true, index: true},
            counter: {type: "number", required: true},
            deviceType: {type: "string", required: true},
            backedUp: {type: "boolean", required: true},
            transports: {type: "string", required: false},
            createdAt: {type: "date", required: false},
            aaguid: {type: "string", required: false}
          }
        }
      }
      return base unless custom_schema.is_a?(Hash)

      base.merge(custom_schema) do |_key, old_value, new_value|
        (old_value.is_a?(Hash) && new_value.is_a?(Hash)) ? old_value.merge(new_value) : new_value
      end
    end

    def passkey_store_challenge(ctx, config, challenge, user_id)
      verification_token = Crypto.random_string(32)
      cookie = passkey_challenge_cookie(ctx, config)
      ctx.set_signed_cookie(cookie.name, verification_token, ctx.context.secret, cookie.attributes.merge(max_age: PASSKEY_CHALLENGE_MAX_AGE))
      ctx.context.internal_adapter.create_verification_value(
        identifier: verification_token,
        value: JSON.generate({
          expectedChallenge: challenge,
          userData: {id: user_id}
        }),
        expiresAt: Time.now + PASSKEY_CHALLENGE_MAX_AGE
      )
    end

    def passkey_find_challenge(ctx, verification_token)
      verification = ctx.context.internal_adapter.find_verification_value(verification_token)
      return nil unless verification && !Routes.expired_time?(verification["expiresAt"])

      JSON.parse(verification.fetch("value"))
    rescue JSON::ParserError
      nil
    end

    def passkey_challenge_token(ctx, config)
      ctx.get_signed_cookie(passkey_challenge_cookie(ctx, config).name, ctx.context.secret)
    end

    def passkey_challenge_cookie(ctx, config)
      ctx.context.create_auth_cookie(config.dig(:advanced, :web_authn_challenge_cookie), max_age: PASSKEY_CHALLENGE_MAX_AGE)
    end

    def passkey_configure_webauthn(config, ctx, origin: nil)
      WebAuthn.configuration.rp_id = passkey_rp_id(config, ctx)
      WebAuthn.configuration.rp_name = config[:rp_name] || ctx.context.app_name
      WebAuthn.configuration.allowed_origins = [origin || config[:origin] || ctx.context.options.base_url].compact
    end

    def passkey_origin(config, ctx)
      config[:origin] || ctx.headers["origin"]
    end

    def passkey_rp_id(config, ctx)
      return config[:rp_id] if config[:rp_id]

      URI.parse(ctx.context.options.base_url.to_s).host || "localhost"
    rescue URI::InvalidURIError
      "localhost"
    end

    def passkey_authenticator_selection(config, query)
      selection = normalize_hash(config[:authenticator_selection] || {})
      attachment = query[:authenticator_attachment]
      selection[:authenticator_attachment] = attachment if attachment
      {
        resident_key: selection[:resident_key] || "preferred",
        user_verification: selection[:user_verification] || "preferred",
        authenticator_attachment: selection[:authenticator_attachment]
      }.compact
    end

    def passkey_webauthn_response(value)
      data = normalize_hash(value || {})
      response = normalize_hash(data[:response] || {})
      webauthn = {
        "type" => data[:type],
        "id" => data[:id],
        "rawId" => data[:raw_id],
        "authenticatorAttachment" => data[:authenticator_attachment],
        "clientExtensionResults" => data[:client_extension_results] || {},
        "response" => {
          "attestationObject" => response[:attestation_object],
          "clientDataJSON" => response[:client_data_json],
          "transports" => response[:transports],
          "authenticatorData" => response[:authenticator_data],
          "signature" => response[:signature],
          "userHandle" => response[:user_handle]
        }.compact
      }.compact
      webauthn["rawId"] ||= webauthn["id"]
      webauthn
    end

    def passkey_attestation_response(credential)
      credential.instance_variable_get(:@response)
    end

    def passkey_authenticator_data(credential)
      passkey_attestation_response(credential)&.authenticator_data
    end

    def passkey_wire(record)
      return record unless record.is_a?(Hash)

      output = record.dup
      output["credentialID"] = output.delete("credentialId") if output.key?("credentialId")
      output
    end

    def passkey_credential_id(record)
      record["credentialID"] || record["credentialId"] || record[:credentialID] || record[:credential_id]
    end

    def passkey_credential_descriptor(record)
      descriptor = {
        id: passkey_credential_id(record),
        type: "public-key"
      }
      transports = (record["transports"] || record[:transports]).to_s.split(",").map(&:strip).reject(&:empty?)
      descriptor[:transports] = transports if transports.any?
      descriptor
    end
  end
end
