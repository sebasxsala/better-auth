# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Routes
      module_function

      def endpoints(config)
        endpoints = {stripe_webhook: BetterAuth::Plugins.stripe_webhook_endpoint(config)}
        return endpoints unless config.dig(:subscription, :enabled)

        endpoints.merge(
          upgrade_subscription: BetterAuth::Stripe::Routes::UpgradeSubscription.endpoint(config),
          cancel_subscription_callback: BetterAuth::Plugins.stripe_cancel_callback_endpoint(config),
          cancel_subscription: BetterAuth::Plugins.stripe_cancel_subscription_endpoint(config),
          restore_subscription: BetterAuth::Plugins.stripe_restore_subscription_endpoint(config),
          list_active_subscriptions: BetterAuth::Plugins.stripe_list_subscriptions_endpoint(config),
          subscription_success: BetterAuth::Plugins.stripe_success_endpoint(config),
          create_billing_portal: BetterAuth::Plugins.stripe_billing_portal_endpoint(config)
        )
      end
    end
  end
end
