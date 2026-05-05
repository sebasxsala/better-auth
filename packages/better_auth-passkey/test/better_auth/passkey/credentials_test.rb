# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPasskeyCredentialsTest < Minitest::Test
  def test_credential_descriptor_matches_upstream_registration_exclude_shape
    descriptor = BetterAuth::Passkey::Credentials.credential_descriptor(
      {"credentialID" => "credential-one", "transports" => "internal, usb"},
      kind: :exclude
    )

    assert_equal({id: "credential-one", transports: ["internal", "usb"]}, descriptor)
  end

  def test_credential_descriptor_matches_upstream_authentication_allow_shape
    descriptor = BetterAuth::Passkey::Credentials.credential_descriptor(
      {credential_id: "credential-one", transports: nil}
    )

    assert_equal({id: "credential-one", type: "public-key"}, descriptor)
  end

  def test_webauthn_response_normalizes_snake_case_browser_payload
    response = BetterAuth::Passkey::Credentials.webauthn_response(
      id: "credential-id",
      raw_id: "raw-id",
      authenticator_attachment: "platform",
      client_extension_results: {credProps: true},
      response: {
        client_data_json: "client-data",
        attestation_object: "attestation",
        transports: ["internal"]
      }
    )

    assert_equal "credential-id", response.fetch("id")
    assert_equal "raw-id", response.fetch("rawId")
    assert_equal "platform", response.fetch("authenticatorAttachment")
    assert_equal({cred_props: true}, response.fetch("clientExtensionResults"))
    assert_equal "client-data", response.fetch("response").fetch("clientDataJSON")
    assert_equal "attestation", response.fetch("response").fetch("attestationObject")
  end

  def test_attestation_response_uses_public_response_reader
    response = Object.new
    credential = Class.new do
      define_method(:initialize) { |value| @value = value }

      def response
        @value
      end

      def instance_variable_get(_name)
        raise "private state should not be read"
      end
    end.new(response)

    assert_same response, BetterAuth::Passkey::Credentials.attestation_response(credential)
  end

  def test_wire_shape_preserves_upstream_credential_id_key
    assert_equal(
      {"id" => "passkey-1", "credentialID" => "credential-one"},
      BetterAuth::Passkey::Credentials.wire({"id" => "passkey-1", "credentialId" => "credential-one"})
    )
  end
end
