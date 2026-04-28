# frozen_string_literal: true

require "json"
require "forwardable"
require "webauthn"
require "webauthn/fake_client"
require_relative "../test_helper"

class BetterAuthPluginsPasskeyTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"
  ORIGIN = "http://localhost:3000"

  def test_registers_and_authenticates_with_real_webauthn_challenges
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "passkey@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)

    registration = auth.api.generate_passkey_registration_options(
      headers: {"cookie" => cookie},
      return_headers: true
    )
    registration_options = registration.fetch(:response)
    registration_cookie = [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; ")

    credential_response = client.create(
      challenge: registration_options.fetch(:challenge),
      rp_id: "localhost"
    )
    passkey = auth.api.verify_passkey_registration(
      headers: {"cookie" => registration_cookie, "origin" => ORIGIN},
      body: {name: "Laptop Touch ID", response: credential_response}
    )

    assert_equal "Laptop Touch ID", passkey.fetch("name")
    assert_equal "passkey@example.com", auth.context.internal_adapter.find_user_by_id(passkey.fetch("userId")).fetch("email")
    assert_equal credential_response.fetch("id"), passkey.fetch("credentialID")
    assert passkey.fetch("publicKey")
    assert_equal 0, passkey.fetch("counter")
    assert_equal "singleDevice", passkey.fetch("deviceType")
    assert_equal "internal", passkey.fetch("transports")

    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    authentication_options = authentication.fetch(:response)
    authentication_cookie = cookie_header(authentication.fetch(:headers).fetch("set-cookie"))
    assertion_response = client.get(
      challenge: authentication_options.fetch(:challenge),
      rp_id: "localhost"
    )

    status, headers, body = auth.api.verify_passkey_authentication(
      headers: {"cookie" => authentication_cookie, "origin" => ORIGIN},
      body: {response: assertion_response},
      as_response: true
    )
    data = JSON.parse(body.join)

    assert_equal 200, status
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("session").fetch("token"))
    assert_equal "passkey@example.com", data.fetch("user").fetch("email")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="

    updated_passkey = auth.context.adapter.find_one(model: "passkey", where: [{field: "id", value: passkey.fetch("id")}])
    assert_operator updated_passkey.fetch("counter"), :>, 0
  end

  def test_passkey_first_registration_resolves_user_context_extensions_and_callback
    captured = {}
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            require_session: false,
            extensions: {credProps: true},
            resolve_user: lambda do |data|
              captured[:resolve_context] = data.fetch(:context)
              {id: captured.fetch(:user).fetch("id"), name: "resolved@example.com", display_name: "Resolved User"}
            end,
            after_verification: lambda do |data|
              captured[:after_context] = data.fetch(:context)
              captured[:after_user] = data.fetch(:user)
              captured[:after_client_data] = data.fetch(:client_data)
              nil
            end
          }
        )
      ]
    )
    captured[:user] = auth.context.internal_adapter.create_user(email: "resolved@example.com", name: "Resolved User", emailVerified: true)
    client = WebAuthn::FakeClient.new(ORIGIN)

    registration = auth.api.generate_passkey_registration_options(
      query: {context: "signed-registration-token", name: "Primary"},
      return_headers: true
    )
    registration_options = registration.fetch(:response)
    challenge = latest_passkey_verification(auth)

    assert_equal "signed-registration-token", captured[:resolve_context]
    assert_equal({credProps: true}, registration_options.fetch(:extensions))
    stored_challenge = JSON.parse(challenge.fetch("value"))
    assert_equal "signed-registration-token", stored_challenge.fetch("context")
    assert_equal "resolved@example.com", stored_challenge.fetch("userData").fetch("name")
    assert_equal "Resolved User", stored_challenge.fetch("userData").fetch("displayName")

    response = client.create(challenge: registration_options.fetch(:challenge), rp_id: "localhost")
    passkey = auth.api.verify_passkey_registration(
      headers: {"cookie" => cookie_header(registration.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
      body: {name: "Primary", response: response}
    )

    assert_equal captured.fetch(:user).fetch("id"), passkey.fetch("userId")
    assert_equal "signed-registration-token", captured[:after_context]
    assert_equal "resolved@example.com", captured.fetch(:after_user).fetch(:name)
    assert_equal response.fetch("id"), captured.fetch(:after_client_data).fetch("id")
  end

  def test_passkey_first_registration_requires_resolver_and_valid_user
    missing_resolver = build_auth(
      plugins: [BetterAuth::Plugins.passkey(registration: {require_session: false})]
    )

    missing = assert_raises(BetterAuth::APIError) do
      missing_resolver.api.generate_passkey_registration_options
    end
    assert_equal 400, missing.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("RESOLVE_USER_REQUIRED"), missing.message

    invalid_resolver = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            require_session: false,
            resolve_user: ->(_data) { {id: "resolved-user-id"} }
          }
        )
      ]
    )

    invalid = assert_raises(BetterAuth::APIError) do
      invalid_resolver.api.generate_passkey_registration_options
    end
    assert_equal 400, invalid.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("RESOLVED_USER_INVALID"), invalid.message
  end

  def test_passkey_first_registration_rejects_invalid_after_verification_user_id
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          registration: {
            require_session: false,
            resolve_user: ->(_data) { {id: "resolved-user-id", name: "resolved@example.com"} },
            after_verification: ->(_data) { {user_id: 123} }
          }
        )
      ]
    )
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => cookie_header(registration.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
        body: {response: response}
      )
    end
    assert_equal 400, invalid.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("RESOLVED_USER_INVALID"), invalid.message
  end

  def test_authentication_extensions_callback_and_array_origin
    captured = {}
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          origin: ["https://app.example.test", ORIGIN],
          authentication: {
            extensions: ->(data) {
              captured[:extensions_ctx] = data.fetch(:ctx)
              {appid: "https://legacy.example.test"}
            },
            after_verification: ->(data) {
              captured[:auth_client_data] = data.fetch(:client_data)
              captured[:auth_verification] = data.fetch(:verification)
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "array-origin@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    passkey = auth.api.verify_passkey_registration(
      headers: {"cookie" => [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; "), "origin" => ORIGIN},
      body: {response: response}
    )

    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)

    assert_equal({appid: "https://legacy.example.test"}, authentication.fetch(:response).fetch(:extensions))
    assert captured[:extensions_ctx]

    assertion = client.get(challenge: authentication.fetch(:response).fetch(:challenge), rp_id: "localhost")
    result = auth.api.verify_passkey_authentication(
      headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
      body: {response: assertion}
    )

    assert_equal passkey.fetch("userId"), result.fetch(:user).fetch("id")
    assert_equal assertion.fetch("id"), captured.fetch(:auth_client_data).fetch("id")
    assert captured[:auth_verification]
  end

  def test_lists_updates_and_deletes_only_the_current_users_passkeys
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "first-passkey@example.com")
    second_cookie = sign_up_cookie(auth, email: "second-passkey@example.com")
    first_user = auth.api.get_session(headers: {"cookie" => first_cookie})[:user]
    second_user = auth.api.get_session(headers: {"cookie" => second_cookie})[:user]
    first = create_passkey(auth, user_id: first_user["id"], name: "First")
    second = create_passkey(auth, user_id: second_user["id"], name: "Second")

    listed = auth.api.list_passkeys(headers: {"cookie" => first_cookie})

    assert_equal [first.fetch("id")], listed.map { |passkey| passkey.fetch("id") }

    updated = auth.api.update_passkey(
      headers: {"cookie" => first_cookie},
      body: {id: first.fetch("id"), name: "Renamed"}
    )
    assert_equal "Renamed", updated.fetch(:passkey).fetch("name")

    unauthorized = assert_raises(BetterAuth::APIError) do
      auth.api.delete_passkey(headers: {"cookie" => first_cookie}, body: {id: second.fetch("id")})
    end
    assert_equal 401, unauthorized.status_code

    deleted = auth.api.delete_passkey(headers: {"cookie" => first_cookie}, body: {id: first.fetch("id")})

    assert_equal({status: true}, deleted)
    assert_empty auth.api.list_passkeys(headers: {"cookie" => first_cookie})
  end

  def test_option_shapes_include_transport_details_and_per_request_expiration
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "shape@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    create_passkey(auth, user_id: user.fetch("id"), name: "Security Key", credential_id: "credential-one", transports: "internal,usb")

    before_registration = Time.now
    registration = auth.api.generate_passkey_registration_options(
      headers: {"cookie" => cookie},
      query: {authenticatorAttachment: "platform", name: "Work laptop"},
      return_headers: true
    )
    registration_options = registration.fetch(:response)
    registration_verification = latest_passkey_verification(auth)

    assert_equal "Work laptop", registration_options.fetch(:user).fetch(:name)
    assert_equal "platform", registration_options.fetch(:authenticatorSelection).fetch(:authenticatorAttachment)
    assert_equal [{id: "credential-one", type: "public-key", transports: ["internal", "usb"]}], registration_options.fetch(:excludeCredentials)
    assert_operator Time.parse(registration_verification.fetch("expiresAt").to_s), :>, before_registration

    before_authentication = Time.now
    authentication = auth.api.generate_passkey_authentication_options(headers: {"cookie" => cookie})
    authentication_verification = latest_passkey_verification(auth)

    assert_equal [{id: "credential-one", type: "public-key", transports: ["internal", "usb"]}], authentication.fetch(:allowCredentials)
    assert_equal "preferred", authentication.fetch(:userVerification)
    assert_operator Time.parse(authentication_verification.fetch("expiresAt").to_s), :>, before_authentication
  end

  def test_sql_schema_includes_passkey_table
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.passkey]
    )

    sql = BetterAuth::Schema::SQL.create_statements(config, dialect: :postgres).join("\n")

    assert_includes sql, 'CREATE TABLE IF NOT EXISTS "passkeys"'
    assert_includes sql, '"credential_id" text NOT NULL'
    assert_includes sql, 'CREATE INDEX IF NOT EXISTS "index_passkeys_on_user_id" ON "passkeys" ("user_id")'
  end

  def test_rejects_expired_challenge_and_delete_not_found_message
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "expired-challenge@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    challenge_cookie = cookie_header(registration.fetch(:headers).fetch("set-cookie"))
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    verification = latest_passkey_verification(auth)
    auth.context.adapter.update(
      model: "verification",
      where: [{field: "id", value: verification.fetch("id")}],
      update: {expiresAt: Time.now - 1}
    )

    expired = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => [cookie, challenge_cookie].join("; "), "origin" => ORIGIN},
        body: {response: response}
      )
    end
    assert_equal 400, expired.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND"), expired.message

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.delete_passkey(headers: {"cookie" => cookie}, body: {id: "missing-passkey"})
    end
    assert_equal 404, missing.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("PASSKEY_NOT_FOUND"), missing.message
  end

  def test_rejects_missing_challenge_and_wrong_registration_user
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "first-challenge@example.com")
    second_cookie = sign_up_cookie(auth, email: "second-challenge@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => first_cookie, "origin" => ORIGIN},
        body: {response: client.create(challenge: WebAuthn::Credential.options_for_create(user: {id: "u", name: "u"}).challenge)}
      )
    end
    assert_equal 400, missing.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("CHALLENGE_NOT_FOUND"), missing.message

    registration = auth.api.generate_passkey_registration_options(
      headers: {"cookie" => first_cookie},
      return_headers: true
    )
    registration_cookie = cookie_header(registration.fetch(:headers).fetch("set-cookie"))
    response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")

    wrong_user = assert_raises(BetterAuth::APIError) do
      auth.api.verify_passkey_registration(
        headers: {"cookie" => [second_cookie, registration_cookie].join("; "), "origin" => ORIGIN},
        body: {response: response}
      )
    end
    assert_equal 401, wrong_user.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"), wrong_user.message
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({
      base_url: ORIGIN,
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.passkey]
    }.merge(options))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Passkey User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def create_passkey(auth, user_id:, name:, credential_id: "#{name}-credential", transports: "internal")
    auth.context.adapter.create(
      model: "passkey",
      data: {
        userId: user_id,
        name: name,
        publicKey: "mock-public-key",
        credentialID: credential_id,
        counter: 0,
        deviceType: "singleDevice",
        backedUp: false,
        transports: transports,
        createdAt: Time.now
      }
    )
  end

  def latest_passkey_verification(auth)
    auth.context.adapter.find_many(model: "verification").max_by { |entry| entry.fetch("createdAt") || Time.at(0) }
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end
end
