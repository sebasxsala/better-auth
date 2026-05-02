# frozen_string_literal: true

module BetterAuth
  module SSO
    module Linking
      module OrgAssignment
        module_function

        def assign_organization_from_provider(ctx, provider:, user:, profile: {}, token: nil, provisioning_options: nil, config: {})
          organization_id = fetch_value(provider, :organization_id)
          return if organization_id.to_s.empty?

          options = normalized_provisioning_options(provisioning_options, config)
          return if options[:disabled]
          return unless organization_plugin?(ctx)
          return if member_exists?(ctx, organization_id, fetch_value(user, :id))

          role = organization_role(
            options,
            user: user,
            user_info: fetch_value(profile || {}, :raw_attributes) || {},
            token: token,
            provider: provider
          )
          create_member(ctx, organization_id, fetch_value(user, :id), role)
        end

        def assign_organization_by_domain(ctx, user:, provisioning_options: nil, domain_verification: nil, config: {})
          options = normalized_provisioning_options(provisioning_options, config)
          return if options[:disabled]
          return unless organization_plugin?(ctx)

          domain_config = BetterAuth::Plugins.normalize_hash(domain_verification || config[:domain_verification] || {})
          domain = fetch_value(user, :email).to_s.split("@", 2)[1]
          return if domain.to_s.empty?

          where = [{field: "domain", value: domain}]
          where << {field: "domainVerified", value: true} if domain_config[:enabled]
          provider = ctx.context.adapter.find_one(model: "ssoProvider", where: where)

          unless provider
            fallback_where = domain_config[:enabled] ? [{field: "domainVerified", value: true}] : []
            providers = ctx.context.adapter.find_many(model: "ssoProvider", where: fallback_where)
            provider = providers.find do |entry|
              (!domain_config[:enabled] || fetch_value(entry, :domain_verified)) &&
                BetterAuth::SSO::Utils.domain_matches?(domain, fetch_value(entry, :domain))
            end
          end

          organization_id = fetch_value(provider || {}, :organization_id)
          return if organization_id.to_s.empty?
          return if member_exists?(ctx, organization_id, fetch_value(user, :id))

          role = organization_role(
            options,
            user: user,
            user_info: {},
            provider: provider
          )
          create_member(ctx, organization_id, fetch_value(user, :id), role)
        end

        def normalized_provisioning_options(provisioning_options, config)
          BetterAuth::Plugins.normalize_hash(provisioning_options || config[:organization_provisioning] || {})
        end

        def organization_plugin?(ctx)
          context = ctx.context
          return context.hasPlugin("organization") if context.respond_to?(:hasPlugin)
          return context.has_plugin?("organization") if context.respond_to?(:has_plugin?)

          plugins = context.options.respond_to?(:plugins) ? context.options.plugins : []
          plugins.any? { |plugin| plugin.respond_to?(:id) && plugin.id == "organization" }
        end

        def member_exists?(ctx, organization_id, user_id)
          ctx.context.adapter.find_one(
            model: "member",
            where: [
              {field: "organizationId", value: organization_id},
              {field: "userId", value: user_id}
            ]
          )
        end

        def organization_role(options, user:, user_info:, provider:, token: nil)
          get_role = options[:get_role]
          if get_role.respond_to?(:call)
            return get_role.call(
              user: user,
              userInfo: user_info,
              token: token,
              provider: provider
            )
          end

          options[:default_role] || options[:role] || "member"
        end

        def create_member(ctx, organization_id, user_id, role)
          ctx.context.adapter.create(
            model: "member",
            data: {
              organizationId: organization_id,
              userId: user_id,
              role: role,
              createdAt: Time.now
            }
          )
        end

        def fetch_value(data, key)
          BetterAuth::Plugins.sso_fetch(data, key)
        end
      end
    end
  end
end
