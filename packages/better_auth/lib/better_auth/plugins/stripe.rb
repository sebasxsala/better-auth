# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    STRIPE_ERROR_CODES = {
      "EMAIL_VERIFICATION_REQUIRED" => "Email verification required",
      "ORGANIZATION_NOT_FOUND" => "Organization not found",
      "STRIPE_SIGNATURE_NOT_FOUND" => "Stripe signature header not found",
      "INVALID_REQUEST_BODY" => "Invalid request body"
    }.freeze

    def stripe(options = {})
      config = normalize_hash(options)
      Plugin.new(
        id: "stripe",
        init: ->(ctx) { {context: {schema: Schema.auth_tables(ctx.options)}} },
        schema: stripe_schema(config),
        endpoints: stripe_endpoints(config),
        error_codes: STRIPE_ERROR_CODES,
        options: config.merge(database_hooks: stripe_database_hooks(config))
      )
    end

    def stripe_schema(config)
      schema = {
        user: {
          fields: {
            stripeCustomerId: {type: "string", required: false}
          }
        }
      }
      if config.dig(:subscription, :enabled)
        schema[:subscription] = {
          fields: {
            plan: {type: "string", required: true},
            referenceId: {type: "string", required: true},
            stripeCustomerId: {type: "string", required: false},
            stripeSubscriptionId: {type: "string", required: false},
            status: {type: "string", required: false, default_value: "incomplete"},
            periodStart: {type: "date", required: false},
            periodEnd: {type: "date", required: false},
            trialStart: {type: "date", required: false},
            trialEnd: {type: "date", required: false},
            cancelAtPeriodEnd: {type: "boolean", required: false, default_value: false},
            cancelAt: {type: "date", required: false},
            canceledAt: {type: "date", required: false},
            endedAt: {type: "date", required: false},
            seats: {type: "number", required: false}
          }
        }
      end
      if config.dig(:organization, :enabled)
        schema[:organization] = {fields: {stripeCustomerId: {type: "string", required: false}}}
      end
      schema
    end

    def stripe_endpoints(config)
      endpoints = {stripe_webhook: stripe_webhook_endpoint(config)}
      return endpoints unless config.dig(:subscription, :enabled)

      endpoints.merge(
        upgrade_subscription: stripe_upgrade_subscription_endpoint(config),
        cancel_subscription_callback: stripe_cancel_callback_endpoint,
        cancel_subscription: stripe_cancel_subscription_endpoint(config),
        restore_subscription: stripe_restore_subscription_endpoint(config),
        list_active_subscriptions: stripe_list_subscriptions_endpoint,
        subscription_success: stripe_success_endpoint,
        create_billing_portal: stripe_billing_portal_endpoint(config)
      )
    end

    def stripe_database_hooks(config)
      return {} unless config[:create_customer_on_sign_up]

      {
        user: {
          create: {
            before: lambda do |data, _ctx|
              next unless data["email"] && !data["stripeCustomerId"]

              customer = stripe_client(config).customers.create(email: data["email"], name: data["name"], metadata: {userId: data["id"], customerType: "user"})
              {data: {stripeCustomerId: stripe_id(customer)}}
            end
          }
        }
      }
    end

    def stripe_upgrade_subscription_endpoint(config)
      Endpoint.new(path: "/subscription/upgrade", method: "POST") do |ctx|
        session = Routes.current_session(ctx, allow_nil: true)
        body = normalize_hash(ctx.body)
        if (body[:customer_type] || "user") == "organization"
          raise APIError.new("BAD_REQUEST", message: "Organization integration requires the organization plugin")
        end
        raise APIError.new("UNAUTHORIZED") unless session

        user = session.fetch(:user)
        customer_id = user["stripeCustomerId"] || stripe_create_customer(config, ctx, user)
        checkout = stripe_client(config).checkout.sessions.create(
          customer: customer_id,
          success_url: body[:success_url],
          cancel_url: body[:cancel_url],
          metadata: {referenceId: user.fetch("id"), customerType: "user", plan: body[:plan]}
        )
        subscription_id = stripe_fetch(checkout, "subscription") || "checkout-subscription"
        ctx.context.adapter.create(
          model: "subscription",
          data: {
            plan: body[:plan],
            referenceId: user.fetch("id"),
            stripeCustomerId: customer_id,
            stripeSubscriptionId: subscription_id,
            status: "incomplete"
          }
        )
        ctx.json({url: stripe_fetch(checkout, "url")})
      end
    end

    def stripe_cancel_subscription_endpoint(config)
      Endpoint.new(path: "/subscription/cancel", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        subscription = stripe_current_subscription!(ctx, session, normalize_hash(ctx.body)[:subscription_id])
        stripe_client(config).subscriptions.update(subscription.fetch("stripeSubscriptionId"), cancel_at_period_end: true) if subscription["stripeSubscriptionId"]
        ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {status: "canceled", cancelAtPeriodEnd: true, canceledAt: Time.now})
        ctx.json({success: true})
      end
    end

    def stripe_restore_subscription_endpoint(config)
      Endpoint.new(path: "/subscription/restore", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        subscription = stripe_current_subscription!(ctx, session, normalize_hash(ctx.body)[:subscription_id])
        stripe_client(config).subscriptions.update(subscription.fetch("stripeSubscriptionId"), cancel_at_period_end: false) if subscription["stripeSubscriptionId"]
        ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {status: "active", cancelAtPeriodEnd: false, cancelAt: nil, canceledAt: nil})
        ctx.json({success: true})
      end
    end

    def stripe_list_subscriptions_endpoint
      Endpoint.new(path: "/subscription/list", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        subscriptions = ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: session.fetch(:user).fetch("id")}])
        ctx.json({subscriptions: subscriptions})
      end
    end

    def stripe_billing_portal_endpoint(config)
      Endpoint.new(path: "/subscription/billing-portal", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        user = session.fetch(:user)
        customer_id = user["stripeCustomerId"] || stripe_create_customer(config, ctx, user)
        portal = stripe_client(config).billing_portal.sessions.create(customer: customer_id, return_url: normalize_hash(ctx.body)[:return_url])
        ctx.json({url: stripe_fetch(portal, "url")})
      end
    end

    def stripe_cancel_callback_endpoint
      Endpoint.new(path: "/subscription/cancel/callback", method: "GET") do |ctx|
        ctx.redirect(ctx.query[:callbackURL] || ctx.query["callbackURL"] || "/")
      end
    end

    def stripe_success_endpoint
      Endpoint.new(path: "/subscription/success", method: "GET") do |ctx|
        ctx.redirect(ctx.query[:callbackURL] || ctx.query["callbackURL"] || "/")
      end
    end

    def stripe_webhook_endpoint(config)
      Endpoint.new(path: "/stripe/webhook", method: "POST") do |ctx|
        signature = ctx.headers["stripe-signature"]
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("STRIPE_SIGNATURE_NOT_FOUND")) if signature.to_s.empty?

        event = if stripe_client(config).respond_to?(:webhooks)
          stripe_client(config).webhooks.construct_event(ctx.body, signature, config[:stripe_webhook_secret])
        else
          ctx.body
        end
        stripe_handle_event(ctx, event)
        ctx.json({received: true})
      rescue APIError
        raise
      rescue => error
        raise APIError.new("BAD_REQUEST", message: error.message)
      end
    end

    def stripe_handle_event(ctx, event)
      event = normalize_hash(event)
      type = event[:type].to_s
      object = normalize_hash(event.dig(:data, :object) || {})
      return unless type.start_with?("customer.subscription.")

      subscription = ctx.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: object[:id]}])
      return unless subscription

      ctx.context.adapter.update(
        model: "subscription",
        where: [{field: "id", value: subscription.fetch("id")}],
        update: {
          status: object[:status],
          periodStart: stripe_time(object[:current_period_start]),
          periodEnd: stripe_time(object[:current_period_end]),
          cancelAtPeriodEnd: object[:cancel_at_period_end],
          cancelAt: stripe_time(object[:cancel_at]),
          canceledAt: stripe_time(object[:canceled_at]),
          endedAt: stripe_time(object[:ended_at])
        }.compact
      )
    end

    def stripe_current_subscription!(ctx, session, subscription_id)
      subscription = ctx.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription_id}])
      raise APIError.new("NOT_FOUND", message: "Subscription not found") unless subscription
      raise APIError.new("FORBIDDEN", message: "Subscription does not belong to user") unless subscription.fetch("referenceId") == session.fetch(:user).fetch("id")

      subscription
    end

    def stripe_create_customer(config, ctx, user)
      customer = stripe_client(config).customers.create(email: user["email"], name: user["name"], metadata: {userId: user["id"], customerType: "user"})
      id = stripe_id(customer)
      ctx.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: id)
      id
    end

    def stripe_client(config)
      config[:stripe_client] || config[:client] || raise(APIError.new("INTERNAL_SERVER_ERROR", message: "Stripe client is required"))
    end

    def stripe_id(object)
      stripe_fetch(object, "id")
    end

    def stripe_fetch(object, key)
      object[key] || object[key.to_sym]
    end

    def stripe_time(value)
      return nil unless value

      Time.at(value.to_i)
    end
  end
end
