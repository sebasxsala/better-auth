# frozen_string_literal: true

module BetterAuth
  module Passkey
    module Credentials
      module_function

      def webauthn_response(value)
        data = BetterAuth::Passkey::Utils.normalize_hash(value || {})
        response = BetterAuth::Passkey::Utils.normalize_hash(data[:response] || {})
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

      def attestation_response(credential)
        credential.instance_variable_get(:@response)
      end

      def authenticator_data(credential)
        attestation_response(credential)&.authenticator_data
      end

      def wire(record)
        return record unless record.is_a?(Hash)

        output = record.dup
        output["credentialID"] = output.delete("credentialId") if output.key?("credentialId")
        output
      end

      def credential_id(record)
        record["credentialID"] || record["credentialId"] || record[:credentialID] || record[:credential_id]
      end

      def credential_descriptor(record, kind: :allow)
        descriptor = {id: credential_id(record)}
        descriptor[:type] = "public-key" if kind == :allow
        transports = (record["transports"] || record[:transports]).to_s.split(",").map(&:strip).reject(&:empty?)
        descriptor[:transports] = transports if transports.any?
        descriptor
      end
    end
  end
end
