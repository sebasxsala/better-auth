# frozen_string_literal: true

module BetterAuth
  module SSO
    module Linking
      module OrgAssignment
        module_function

        def assign_organization_from_provider(ctx, provider:, user:, config: {})
          BetterAuth::Plugins.sso_assign_organization_membership(ctx, provider, user, config)
        end

        def assign_organization_by_domain(ctx, user:, config: {})
          providers = ctx.context.adapter.find_many(model: "ssoProvider")
          provider = providers.find do |entry|
            entry["organizationId"].to_s != "" &&
              BetterAuth::Plugins.sso_email_domain_matches?(user.fetch("email"), entry["domain"]) &&
              (!config.dig(:domain_verification, :enabled) || entry["domainVerified"])
          end
          BetterAuth::Plugins.sso_assign_organization_membership(ctx, provider, user, config) if provider
        end
      end
    end
  end
end
