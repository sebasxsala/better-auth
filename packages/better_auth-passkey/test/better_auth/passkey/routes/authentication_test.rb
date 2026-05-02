# frozen_string_literal: true

require "json"
require "forwardable"
require "webauthn/fake_client"
require_relative "../support"

class BetterAuthPasskeyRoutesAuthenticationTest < Minitest::Test
  include BetterAuthPasskeyTestSupport

  def test_generate_authentication_options_omits_allow_credentials_without_session
    auth = build_auth

    options = auth.api.generate_passkey_authentication_options
    verification = JSON.parse(auth.context.adapter.find_many(model: "verification").last.fetch("value"))

    assert_includes options.keys, :challenge
    assert_includes options.keys, :rpId
    assert_equal "preferred", options.fetch(:userVerification)
    refute_includes options.keys, :allowCredentials
    assert_equal "", verification.fetch("userData").fetch("id")
    refute_includes options.keys, :extensions
    refute_includes options.keys, "extensions"
  end

  def test_generate_authentication_options_includes_current_user_passkeys
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "authentication-route@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    create_passkey(auth, user_id: user.fetch("id"), name: "Route key", credential_id: "route-credential", transports: "internal,usb")

    options = auth.api.generate_passkey_authentication_options(headers: {"cookie" => cookie})

    assert_equal [{id: "route-credential", type: "public-key", transports: ["internal", "usb"]}], options.fetch(:allowCredentials)
  end

  def test_after_verification_receives_upstream_payload_keys
    captured = {}
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.passkey(
          authentication: {
            after_verification: lambda do |data|
              captured[:keys] = data.keys
              captured[:ctx] = data.fetch(:ctx)
              captured[:verification] = data.fetch(:verification)
              captured[:client_data] = data.fetch(:client_data)
            end
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "after-authentication-route@example.com")
    client = WebAuthn::FakeClient.new(ORIGIN)
    registration = auth.api.generate_passkey_registration_options(headers: {"cookie" => cookie}, return_headers: true)
    registration_cookie = [cookie, cookie_header(registration.fetch(:headers).fetch("set-cookie"))].join("; ")
    registration_response = client.create(challenge: registration.fetch(:response).fetch(:challenge), rp_id: "localhost")
    auth.api.verify_passkey_registration(
      headers: {"cookie" => registration_cookie, "origin" => ORIGIN},
      body: {response: registration_response}
    )
    authentication = auth.api.generate_passkey_authentication_options(return_headers: true)
    assertion = client.get(challenge: authentication.fetch(:response).fetch(:challenge), rp_id: "localhost")

    auth.api.verify_passkey_authentication(
      headers: {"cookie" => cookie_header(authentication.fetch(:headers).fetch("set-cookie")), "origin" => ORIGIN},
      body: {response: assertion}
    )

    assert_equal [:ctx, :verification, :client_data], captured.fetch(:keys)
    assert captured.fetch(:ctx)
    assert captured.fetch(:verification)
    assert_equal assertion.fetch("id"), captured.fetch(:client_data).fetch("id")
  end
end
