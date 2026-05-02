# frozen_string_literal: true

require "securerandom"

module BetterAuth
  module Stripe
    module PluginFactory
      module_function

      def build(options = {})
        config = BetterAuth::Plugins.normalize_hash(options)
        BetterAuth::Plugin.new(
          id: "stripe",
          init: ->(ctx) { {context: {schema: BetterAuth::Schema.auth_tables(ctx.options)}} },
          schema: BetterAuth::Stripe::Schema.schema(config),
          endpoints: BetterAuth::Stripe::Routes.endpoints(config),
          error_codes: BetterAuth::Stripe::ERROR_CODES,
          options: config.merge(database_hooks: database_hooks(config), organization_hooks: BetterAuth::Stripe::OrganizationHooks.hooks(config))
        )
      end

      def database_hooks(config)
        return {} unless config[:create_customer_on_sign_up]

        {
          user: {
            create: {
              before: lambda do |data, hook_ctx|
                next unless data["email"] && !data["stripeCustomerId"]

                data["id"] ||= SecureRandom.hex(16)
                customer = BetterAuth::Plugins.stripe_find_or_create_user_customer(config, data, nil, hook_ctx)
                {data: {id: data["id"], stripeCustomerId: BetterAuth::Stripe::Utils.id(customer)}}
              rescue
                nil
              end
            },
            update: {
              after: lambda do |user, _ctx|
                next unless user && user["stripeCustomerId"]

                customer = BetterAuth::Stripe::Utils.client(config).customers.retrieve(user["stripeCustomerId"])
                next if BetterAuth::Stripe::Utils.fetch(customer, "deleted")
                next if BetterAuth::Stripe::Utils.fetch(customer, "email") == user["email"]

                BetterAuth::Stripe::Utils.client(config).customers.update(user["stripeCustomerId"], email: user["email"])
              rescue
                nil
              end
            }
          }
        }
      end
    end
  end
end
