# frozen_string_literal: true

module BetterAuth
  module Plugins
    SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
    SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    SCIM_USER_SCHEMA_ID = "urn:ietf:params:scim:schemas:core:2.0:User"
    SCIM_SUPPORTED_MEDIA_TYPES = ["application/json", "application/scim+json"].freeze

    module_function

    def scim_hidden_metadata(summary, allowed_media_types)
      {
        hide: true,
        allowed_media_types: allowed_media_types,
        openapi: {
          summary: summary,
          responses: scim_openapi_responses
        }
      }
    end

    def scim_openapi_metadata(summary)
      {
        openapi: {
          summary: summary,
          responses: scim_openapi_responses
        }
      }
    end

    def scim_openapi_responses
      {
        "200" => {description: "Success"},
        "400" => {description: "Bad Request"},
        "401" => {description: "Unauthorized"},
        "403" => {description: "Forbidden"},
        "404" => {description: "Not Found"}
      }
    end
  end
end
