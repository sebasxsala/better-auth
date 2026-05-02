# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Routes
      module StripeWebhook
        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/stripe/webhook", method: "POST") do |ctx|
            signature = ctx.headers["stripe-signature"]
            raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("STRIPE_SIGNATURE_NOT_FOUND")) if signature.to_s.empty?

            raise BetterAuth::APIError.new("INTERNAL_SERVER_ERROR", message: BetterAuth::Stripe::ERROR_CODES.fetch("STRIPE_WEBHOOK_SECRET_NOT_FOUND")) if config[:stripe_webhook_secret].to_s.empty?

            event = begin
              if BetterAuth::Plugins.stripe_client(config).respond_to?(:webhooks)
                webhooks = BetterAuth::Plugins.stripe_client(config).webhooks
                if webhooks.respond_to?(:construct_event_async)
                  webhooks.construct_event_async(ctx.body, signature, config[:stripe_webhook_secret])
                else
                  webhooks.construct_event(ctx.body, signature, config[:stripe_webhook_secret])
                end
              else
                ctx.body
              end
            rescue
              raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT"))
            end
            raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT")) unless event
            begin
              BetterAuth::Plugins.stripe_handle_event(ctx, event)
            rescue
              raise BetterAuth::APIError.new("BAD_REQUEST", message: BetterAuth::Stripe::ERROR_CODES.fetch("STRIPE_WEBHOOK_ERROR"))
            end
            ctx.json({success: true})
          end
        end
      end
    end
  end
end
