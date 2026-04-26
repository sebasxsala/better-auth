# frozen_string_literal: true

require "json"
require "forwardable"
require "webauthn"
require "webauthn/fake_client"
require_relative "../../test_helper"

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
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="

    updated_passkey = auth.context.adapter.find_one(model: "passkey", where: [{field: "id", value: passkey.fetch("id")}])
    assert_operator updated_passkey.fetch("counter"), :>, 0
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

  def create_passkey(auth, user_id:, name:)
    auth.context.adapter.create(
      model: "passkey",
      data: {
        userId: user_id,
        name: name,
        publicKey: "mock-public-key",
        credentialID: "#{name}-credential",
        counter: 0,
        deviceType: "singleDevice",
        backedUp: false,
        transports: "internal",
        createdAt: Time.now
      }
    )
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end
end
