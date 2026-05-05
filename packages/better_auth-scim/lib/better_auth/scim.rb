# frozen_string_literal: true

require "better_auth"
require_relative "scim/version"
require_relative "scim/scim_metadata"
require_relative "scim/scim_error"
require_relative "scim/utils"
require_relative "scim/client"
require_relative "scim/user_schemas"
require_relative "scim/scim_resources"
require_relative "scim/mappings"
require_relative "scim/scim_filters"
require_relative "scim/patch_operations"
require_relative "scim/scim_tokens"
require_relative "scim/middlewares"
require_relative "scim/provider_management"
require_relative "scim/validation"
require_relative "scim/routes"
require_relative "plugins/scim"

module BetterAuth
  module SCIM
  end
end
