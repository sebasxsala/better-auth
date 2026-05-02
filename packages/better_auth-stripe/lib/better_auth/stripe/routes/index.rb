# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Routes
      module_function

      def endpoints(config)
        endpoints = {stripe_webhook: BetterAuth::Stripe::Routes::StripeWebhook.endpoint(config)}
        return endpoints unless config.dig(:subscription, :enabled)

        endpoints.merge(
          upgrade_subscription: BetterAuth::Stripe::Routes::UpgradeSubscription.endpoint(config),
          cancel_subscription_callback: BetterAuth::Stripe::Routes::CancelSubscriptionCallback.endpoint(config),
          cancel_subscription: BetterAuth::Stripe::Routes::CancelSubscription.endpoint(config),
          restore_subscription: BetterAuth::Stripe::Routes::RestoreSubscription.endpoint(config),
          list_active_subscriptions: BetterAuth::Stripe::Routes::ListActiveSubscriptions.endpoint(config),
          subscription_success: BetterAuth::Stripe::Routes::SubscriptionSuccess.endpoint(config),
          create_billing_portal: BetterAuth::Stripe::Routes::CreateBillingPortal.endpoint(config)
        )
      end
    end
  end
end
