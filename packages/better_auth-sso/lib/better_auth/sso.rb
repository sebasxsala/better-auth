# frozen_string_literal: true

require "better_auth"
require_relative "sso/version"
require_relative "sso/saml_hooks"
require_relative "sso/saml"
require_relative "plugins/sso"
require_relative "sso/constants"
require_relative "sso/utils"
require_relative "sso/oidc/discovery"
require_relative "sso/oidc/errors"
require_relative "sso/linking/org_assignment"
require_relative "sso/saml/algorithms"
require_relative "sso/saml/assertions"
require_relative "sso/saml/timestamp"
require_relative "sso/saml/parser"
require_relative "sso/routes/helpers"
require_relative "sso/routes/providers"
require_relative "sso/routes/domain_verification"
require_relative "sso/routes/saml_pipeline"
require_relative "sso/routes/sso"
require_relative "sso/saml_state"

module BetterAuth
  module SSO
  end
end
