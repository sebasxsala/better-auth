# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def scim_validate_user_body!(body)
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) unless body[:user_name].is_a?(String)
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if body[:user_name].empty?
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if body.key?(:external_id) && !body[:external_id].is_a?(String)
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if body.key?(:name) && !body[:name].is_a?(Hash)
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if body.key?(:emails) && !body[:emails].is_a?(Array)
      normalize_hash(body[:name] || {}).each_value do |value|
        raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) unless value.is_a?(String)
      end

      Array(body[:emails]).each do |email|
        email = normalize_hash(email)
        value = email[:value]
        raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if email.key?(:primary) && ![true, false].include?(email[:primary])
        raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) unless value.to_s.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
      end
    end

    def scim_validate_patch_body!(body)
      schemas = Array(body[:schemas])
      raise scim_error("BAD_REQUEST", "Invalid schemas for PatchOp") unless schemas.include?("urn:ietf:params:scim:api:messages:2.0:PatchOp")

      Array(body[:operations]).each_with_index do |operation, index|
        op = normalize_hash(operation)[:op]
        next if op.nil? || op.to_s.empty?

        unless op.is_a?(String)
          raise scim_patch_validation_error("[body.Operations.#{index}.op] Invalid input: expected string")
        end

        next if %w[replace add remove].include?(op.downcase)

        raise scim_patch_validation_error("[body.Operations.#{index}.op] Invalid option: expected one of \"replace\"|\"add\"|\"remove\"")
      end
    end

    def scim_patch_validation_error(message)
      APIError.new(
        "BAD_REQUEST",
        message: BASE_ERROR_CODES["VALIDATION_ERROR"],
        body: {code: "VALIDATION_ERROR", message: message}
      )
    end
  end
end
