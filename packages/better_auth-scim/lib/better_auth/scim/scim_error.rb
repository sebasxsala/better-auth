# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def scim_error(status, detail, scim_type: nil)
      body = {
        schemas: [SCIM_ERROR_SCHEMA],
        status: APIError::STATUS_CODES.fetch(status.to_s.upcase, 500).to_s,
        detail: detail
      }
      body[:scimType] = scim_type if scim_type
      APIError.new(status, message: detail, body: body)
    end
  end
end
