# frozen_string_literal: true

require_relative "linking/types"
require_relative "linking/org_assignment"

module BetterAuth
  module SSO
    module Linking
      module_function

      def assign_organization_from_provider(ctx, provider:, user:, config: {})
        OrgAssignment.assign_organization_from_provider(ctx, provider: provider, user: user, config: config)
      end

      def assign_organization_by_domain(ctx, user:, config: {})
        OrgAssignment.assign_organization_by_domain(ctx, user: user, config: config)
      end

      def normalized_profile(profile)
        Types.normalized_profile(profile)
      end
    end
  end
end
