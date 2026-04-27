# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    STRIPE_ERROR_CODES = {
      "UNAUTHORIZED" => "Unauthorized access",
      "EMAIL_VERIFICATION_REQUIRED" => "Email verification required",
      "SUBSCRIPTION_NOT_FOUND" => "Subscription not found",
      "SUBSCRIPTION_PLAN_NOT_FOUND" => "Subscription plan not found",
      "ALREADY_SUBSCRIBED_PLAN" => "You're already subscribed to this plan",
      "REFERENCE_ID_NOT_ALLOWED" => "Reference id is not allowed",
      "CUSTOMER_NOT_FOUND" => "Stripe customer not found for this user",
      "UNABLE_TO_CREATE_CUSTOMER" => "Unable to create customer",
      "UNABLE_TO_CREATE_BILLING_PORTAL" => "Unable to create billing portal session",
      "ORGANIZATION_NOT_FOUND" => "Organization not found",
      "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED" => "Organization subscription is not enabled",
      "AUTHORIZE_REFERENCE_REQUIRED" => "Organization subscriptions require authorizeReference callback to be configured",
      "ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION" => "Cannot delete organization with active subscription",
      "ORGANIZATION_REFERENCE_ID_REQUIRED" => "Reference ID is required. Provide referenceId or set activeOrganizationId in session",
      "SUBSCRIPTION_NOT_ACTIVE" => "Subscription is not active",
      "SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION" => "Subscription is not scheduled for cancellation",
      "STRIPE_SIGNATURE_NOT_FOUND" => "Stripe signature not found",
      "STRIPE_WEBHOOK_SECRET_NOT_FOUND" => "Stripe webhook secret not found",
      "FAILED_TO_CONSTRUCT_STRIPE_EVENT" => "Failed to construct Stripe event",
      "STRIPE_WEBHOOK_ERROR" => "Stripe webhook error",
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
        options: config.merge(database_hooks: stripe_database_hooks(config), organization_hooks: stripe_organization_hooks(config))
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
            seats: {type: "number", required: false},
            limits: {type: "json", required: false}
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
        cancel_subscription_callback: stripe_cancel_callback_endpoint(config),
        cancel_subscription: stripe_cancel_subscription_endpoint(config),
        restore_subscription: stripe_restore_subscription_endpoint(config),
        list_active_subscriptions: stripe_list_subscriptions_endpoint(config),
        subscription_success: stripe_success_endpoint(config),
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

              customer = stripe_find_or_create_user_customer(config, data)
              {data: {stripeCustomerId: stripe_id(customer)}}
            end
          },
          update: {
            after: lambda do |user, _ctx|
              next unless user && user["stripeCustomerId"]

              customer = stripe_client(config).customers.retrieve(user["stripeCustomerId"])
              next if stripe_fetch(customer, "deleted")
              next if stripe_fetch(customer, "email") == user["email"]

              stripe_client(config).customers.update(user["stripeCustomerId"], email: user["email"])
            rescue
              nil
            end
          }
        }
      }
    end

    def stripe_organization_hooks(config)
      return {} unless config.dig(:organization, :enabled)

      {
        after_update_organization: lambda do |data, _ctx|
          organization = data[:organization] || data["organization"]
          next unless organization && organization["stripeCustomerId"]

          customer = stripe_client(config).customers.retrieve(organization["stripeCustomerId"])
          next if stripe_fetch(customer, "deleted")
          next if stripe_fetch(customer, "name") == organization["name"]

          stripe_client(config).customers.update(organization["stripeCustomerId"], name: organization["name"])
        rescue
          nil
        end,
        before_delete_organization: lambda do |data, _ctx|
          organization = data[:organization] || data["organization"]
          next unless organization && organization["stripeCustomerId"]

          subscriptions = stripe_client(config).subscriptions.list(customer: organization["stripeCustomerId"], status: "all", limit: 100)
          active = Array(stripe_fetch(subscriptions, "data")).any? do |subscription|
            !%w[canceled incomplete incomplete_expired].include?(stripe_fetch(subscription, "status").to_s)
          end
          raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION")) if active
        end
      }
    end

    def stripe_upgrade_subscription_endpoint(config)
      Endpoint.new(path: "/subscription/upgrade", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        subscription_options = stripe_subscription_options(config)
        customer_type = (body[:customer_type] || "user").to_s
        reference_id = stripe_reference_id!(ctx, session, customer_type, body[:reference_id], config)
        stripe_authorize_reference!(ctx, session, reference_id, "upgrade-subscription", customer_type, subscription_options, explicit: body.key?(:reference_id))

        user = session.fetch(:user)
        if subscription_options[:require_email_verification] && !user["emailVerified"]
          raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("EMAIL_VERIFICATION_REQUIRED"))
        end

        plan = stripe_plan_by_name(config, body[:plan])
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_PLAN_NOT_FOUND")) unless plan

        subscription_to_update = nil
        if body[:subscription_id]
          subscription_to_update = ctx.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: body[:subscription_id]}])
          raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")) unless subscription_to_update && subscription_to_update["referenceId"] == reference_id
        end

        customer_id = if customer_type == "organization"
          subscription_to_update&.fetch("stripeCustomerId", nil) || stripe_organization_customer(config, ctx, reference_id, body[:metadata])
        else
          subscription_to_update&.fetch("stripeCustomerId", nil) || user["stripeCustomerId"] || stripe_create_customer(config, ctx, user, body[:metadata])
        end

        subscriptions = subscription_to_update ? [subscription_to_update] : ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}])
        active_or_trialing = subscriptions.find { |entry| stripe_active_or_trialing?(entry) }
        active_stripe_subscriptions = stripe_active_subscriptions(config, customer_id)
        active_stripe = active_stripe_subscriptions.find do |entry|
          if subscription_to_update&.fetch("stripeSubscriptionId", nil) || body[:subscription_id]
            stripe_fetch(entry, "id") == subscription_to_update&.fetch("stripeSubscriptionId", nil) || stripe_fetch(entry, "id") == body[:subscription_id]
          elsif active_or_trialing && active_or_trialing["stripeSubscriptionId"]
            stripe_fetch(entry, "id") == active_or_trialing["stripeSubscriptionId"]
          else
            false
          end
        end

        price_id = stripe_price_id(config, plan, body[:annual])
        active_stripe_item = stripe_subscription_item(active_stripe || {})
        stripe_price_id_value = stripe_fetch(stripe_fetch(active_stripe_item || {}, "price") || {}, "id")
        same_plan = active_or_trialing && active_or_trialing["plan"].to_s.downcase == body[:plan].to_s.downcase
        same_seats = active_or_trialing && active_or_trialing["seats"].to_i == (body[:seats] || 1).to_i
        same_price = !active_stripe || stripe_price_id_value == price_id
        valid_period = !active_or_trialing || !active_or_trialing["periodEnd"] || active_or_trialing["periodEnd"] > Time.now
        if active_or_trialing&.fetch("status", nil) == "active" && same_plan && same_seats && same_price && valid_period
          raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("ALREADY_SUBSCRIBED_PLAN"))
        end

        if active_stripe
          portal = stripe_client(config).billing_portal.sessions.create(
            customer: customer_id,
            return_url: stripe_url(ctx, body[:return_url] || "/"),
            flow_data: {
              type: "subscription_update_confirm",
              after_completion: {type: "redirect", redirect: {return_url: stripe_url(ctx, body[:return_url] || "/")}},
              subscription_update_confirm: {
                subscription: stripe_fetch(active_stripe, "id"),
                items: [{id: stripe_fetch(active_stripe_item || {}, "id"), quantity: body[:seats] || 1, price: price_id}]
              }
            }
          )
          next ctx.json(stripe_stringify_keys(portal).merge(redirect: stripe_redirect?(body)))
        end

        incomplete = subscriptions.find { |entry| entry["status"] == "incomplete" }
        subscription = active_or_trialing || incomplete
        if subscription
          update = {plan: plan[:name].to_s.downcase, seats: body[:seats] || 1}
          subscription = ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: update) || subscription.merge(update.transform_keys { |key| Schema.storage_key(key) })
        else
          subscription = ctx.context.adapter.create(
            model: "subscription",
            data: {plan: plan[:name].to_s.downcase, referenceId: reference_id, stripeCustomerId: customer_id, status: "incomplete", seats: body[:seats] || 1, limits: plan[:limits]}
          )
        end

        has_ever_trialed = ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}]).any? do |entry|
          entry["trialStart"] || entry["trialEnd"] || entry["status"] == "trialing"
        end
        free_trial = (!has_ever_trialed && plan[:free_trial]) ? {trial_period_days: plan.dig(:free_trial, :days)} : {}
        metadata = stripe_metadata({userId: user.fetch("id"), subscriptionId: subscription.fetch("id"), referenceId: reference_id}, body[:metadata])
        checkout = stripe_client(config).checkout.sessions.create(
          customer: customer_id,
          customer_update: (customer_type == "user") ? {name: "auto", address: "auto"} : {address: "auto"},
          locale: body[:locale],
          success_url: stripe_url(ctx, "#{ctx.context.base_url}/subscription/success?callbackURL=#{Rack::Utils.escape(body[:success_url] || "/")}&subscriptionId=#{Rack::Utils.escape(subscription.fetch("id"))}"),
          cancel_url: stripe_url(ctx, body[:cancel_url] || "/"),
          line_items: [{price: price_id, quantity: body[:seats] || 1}],
          subscription_data: free_trial.merge(metadata: metadata),
          mode: "subscription",
          client_reference_id: reference_id,
          metadata: metadata
        )
        ctx.json(stripe_stringify_keys(checkout).merge(redirect: stripe_redirect?(body)))
      end
    end

    def stripe_cancel_subscription_endpoint(config)
      Endpoint.new(path: "/subscription/cancel", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        customer_type = (body[:customer_type] || "user").to_s
        reference_id = stripe_reference_id!(ctx, session, customer_type, body[:reference_id], config)
        stripe_authorize_reference!(ctx, session, reference_id, "cancel-subscription", customer_type, stripe_subscription_options(config), explicit: body.key?(:reference_id))
        subscription = stripe_find_subscription_for_action(ctx, reference_id, body[:subscription_id], active_only: true)
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")) unless subscription && subscription["stripeCustomerId"]

        active = stripe_active_subscriptions(config, subscription["stripeCustomerId"])
        if active.empty?
          ctx.context.adapter.delete_many(model: "subscription", where: [{field: "referenceId", value: reference_id}])
          raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND"))
        end
        stripe_subscription = active.find { |entry| stripe_fetch(entry, "id") == subscription["stripeSubscriptionId"] }
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")) unless stripe_subscription

        portal = stripe_client(config).billing_portal.sessions.create(
          customer: subscription["stripeCustomerId"],
          return_url: stripe_url(ctx, "#{ctx.context.base_url}/subscription/cancel/callback?callbackURL=#{Rack::Utils.escape(body[:return_url] || "/")}&subscriptionId=#{Rack::Utils.escape(subscription.fetch("id"))}"),
          flow_data: {type: "subscription_cancel", subscription_cancel: {subscription: stripe_fetch(stripe_subscription, "id")}}
        )
        ctx.json(stripe_stringify_keys(portal).merge(redirect: stripe_redirect?(body)))
      rescue APIError
        raise
      rescue => error
        if error.message.include?("already set to be canceled") && subscription && !stripe_pending_cancel?(subscription)
          stripe_sub = stripe_client(config).subscriptions.retrieve(subscription["stripeSubscriptionId"])
          ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: stripe_subscription_state(stripe_sub, include_status: false))
        end
        raise APIError.new("BAD_REQUEST", message: error.message)
      end
    end

    def stripe_restore_subscription_endpoint(config)
      Endpoint.new(path: "/subscription/restore", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        customer_type = (body[:customer_type] || "user").to_s
        reference_id = stripe_reference_id!(ctx, session, customer_type, body[:reference_id], config)
        stripe_authorize_reference!(ctx, session, reference_id, "restore-subscription", customer_type, stripe_subscription_options(config), explicit: body.key?(:reference_id))
        subscription = stripe_find_subscription_for_action(ctx, reference_id, body[:subscription_id], active_only: false)
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")) unless subscription && subscription["stripeCustomerId"]
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_ACTIVE")) unless stripe_active_or_trialing?(subscription)
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION")) unless stripe_pending_cancel?(subscription)

        active = stripe_active_subscriptions(config, subscription["stripeCustomerId"]).first
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")) unless active

        update_params = if stripe_fetch(active, "cancel_at")
          {cancel_at: ""}
        elsif stripe_fetch(active, "cancel_at_period_end")
          {cancel_at_period_end: false}
        else
          {}
        end
        restored = stripe_client(config).subscriptions.update(stripe_fetch(active, "id"), update_params)
        ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {cancelAtPeriodEnd: false, cancelAt: nil, canceledAt: nil})
        ctx.json(stripe_stringify_keys(restored))
      end
    end

    def stripe_list_subscriptions_endpoint(config)
      Endpoint.new(path: "/subscription/list", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        query = normalize_hash(ctx.query)
        customer_type = (query[:customer_type] || "user").to_s
        reference_id = stripe_reference_id!(ctx, session, customer_type, query[:reference_id], config)
        stripe_authorize_reference!(ctx, session, reference_id, "list-subscription", customer_type, stripe_subscription_options(config), explicit: query.key?(:reference_id))
        plans = stripe_plans(config)
        subscriptions = ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}]).select { |entry| stripe_active_or_trialing?(entry) }
        ctx.json(subscriptions.map do |entry|
          plan = plans.find { |item| item[:name].to_s.downcase == entry["plan"].to_s.downcase }
          entry.merge("limits" => plan&.fetch(:limits, nil), "priceId" => plan&.fetch(:price_id, nil))
        end)
      end
    end

    def stripe_billing_portal_endpoint(config)
      Endpoint.new(path: "/subscription/billing-portal", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        customer_type = (body[:customer_type] || "user").to_s
        reference_id = stripe_reference_id!(ctx, session, customer_type, body[:reference_id], config)
        stripe_authorize_reference!(ctx, session, reference_id, "billing-portal", customer_type, stripe_subscription_options(config), explicit: body.key?(:reference_id))
        customer_id = if customer_type == "organization"
          org = ctx.context.adapter.find_one(model: "organization", where: [{field: "id", value: reference_id}])
          org&.fetch("stripeCustomerId", nil) || stripe_active_subscription(ctx, reference_id)&.fetch("stripeCustomerId", nil)
        else
          session.fetch(:user)["stripeCustomerId"] || stripe_active_subscription(ctx, reference_id)&.fetch("stripeCustomerId", nil)
        end
        raise APIError.new("NOT_FOUND", message: STRIPE_ERROR_CODES.fetch("CUSTOMER_NOT_FOUND")) unless customer_id

        portal = stripe_client(config).billing_portal.sessions.create(customer: customer_id, return_url: stripe_url(ctx, body[:return_url] || "/"), locale: body[:locale])
        ctx.json(stripe_stringify_keys(portal).merge(redirect: stripe_redirect?(body)))
      rescue APIError
        raise
      rescue
        raise APIError.new("INTERNAL_SERVER_ERROR", message: STRIPE_ERROR_CODES.fetch("UNABLE_TO_CREATE_BILLING_PORTAL"))
      end
    end

    def stripe_cancel_callback_endpoint(config = nil)
      Endpoint.new(path: "/subscription/cancel/callback", method: "GET") do |ctx|
        query = normalize_hash(ctx.query)
        callback = query[:callback_url] || "/"
        unless query[:subscription_id]
          raise ctx.redirect(stripe_url(ctx, callback))
        end
        session = Routes.current_session(ctx, allow_nil: true)
        raise ctx.redirect(stripe_url(ctx, callback)) unless session

        subscription = ctx.context.adapter.find_one(model: "subscription", where: [{field: "id", value: query[:subscription_id]}])
        if subscription && !stripe_pending_cancel?(subscription) && subscription["stripeCustomerId"]
          current = stripe_active_subscriptions(config || {}, subscription["stripeCustomerId"]).find { |entry| stripe_fetch(entry, "id") == subscription["stripeSubscriptionId"] }
          if current && stripe_stripe_pending_cancel?(current)
            ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: stripe_subscription_state(current, include_status: true))
            stripe_subscription_options(config || {})[:on_subscription_cancel]&.call({subscription: subscription, stripeSubscription: current, stripe_subscription: current, cancellationDetails: stripe_fetch(current, "cancellation_details"), cancellation_details: stripe_fetch(current, "cancellation_details"), event: nil})
          end
        end
        raise ctx.redirect(stripe_url(ctx, callback))
      end
    end

    def stripe_success_endpoint(config = nil)
      Endpoint.new(path: "/subscription/success", method: "GET") do |ctx|
        query = normalize_hash(ctx.query)
        callback = query[:callback_url] || "/"
        unless query[:subscription_id]
          raise ctx.redirect(stripe_url(ctx, callback))
        end
        session = Routes.current_session(ctx, allow_nil: true)
        raise ctx.redirect(stripe_url(ctx, callback)) unless session

        subscription = ctx.context.adapter.find_one(model: "subscription", where: [{field: "id", value: query[:subscription_id]}])
        raise ctx.redirect(stripe_url(ctx, callback)) unless subscription
        raise ctx.redirect(stripe_url(ctx, callback)) if stripe_active_or_trialing?(subscription)

        customer_id = subscription["stripeCustomerId"] || session.fetch(:user)["stripeCustomerId"]
        raise ctx.redirect(stripe_url(ctx, callback)) unless customer_id

        stripe_subscription = stripe_active_subscriptions(config || {}, customer_id).first
        if stripe_subscription
          item = stripe_subscription_item(stripe_subscription)
          plan = item && stripe_plan_by_price_info(config || {}, stripe_fetch(stripe_fetch(item, "price") || {}, "id"), stripe_fetch(stripe_fetch(item, "price") || {}, "lookup_key"))
          if item && plan
            ctx.context.adapter.update(
              model: "subscription",
              where: [{field: "id", value: subscription.fetch("id")}],
              update: stripe_subscription_state(stripe_subscription, include_status: true).merge(
                plan: plan[:name].to_s.downcase,
                seats: stripe_fetch(item, "quantity") || 1,
                stripeSubscriptionId: stripe_fetch(stripe_subscription, "id")
              )
            )
          end
        end
        raise ctx.redirect(stripe_url(ctx, callback))
      end
    end

    def stripe_webhook_endpoint(config)
      Endpoint.new(path: "/stripe/webhook", method: "POST") do |ctx|
        signature = ctx.headers["stripe-signature"]
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("STRIPE_SIGNATURE_NOT_FOUND")) if signature.to_s.empty?

        raise APIError.new("INTERNAL_SERVER_ERROR", message: STRIPE_ERROR_CODES.fetch("STRIPE_WEBHOOK_SECRET_NOT_FOUND")) if config[:stripe_webhook_secret].to_s.empty?

        event = if stripe_client(config).respond_to?(:webhooks)
          webhooks = stripe_client(config).webhooks
          if webhooks.respond_to?(:construct_event_async) && (!webhooks.respond_to?(:construct_event) || config[:stripe_async_webhooks] || (webhooks.respond_to?(:async) && webhooks.async))
            webhooks.construct_event_async(ctx.body, signature, config[:stripe_webhook_secret])
          else
            webhooks.construct_event(ctx.body, signature, config[:stripe_webhook_secret])
          end
        else
          ctx.body
        end
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT")) unless event
        stripe_handle_event(ctx, event)
        ctx.json({success: true})
      rescue APIError
        raise
      rescue => error
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT") || error.message)
      end
    end

    def stripe_handle_event(ctx, event)
      event = normalize_hash(event)
      type = event[:type].to_s
      case type
      when "checkout.session.completed"
        stripe_on_checkout_completed(ctx, event)
      when "customer.subscription.created"
        stripe_on_subscription_created(ctx, event)
      when "customer.subscription.updated"
        stripe_on_subscription_updated(ctx, event)
      when "customer.subscription.deleted"
        stripe_on_subscription_deleted(ctx, event)
      end
      config = ctx.context.options.plugins.find { |plugin| plugin.id == "stripe" }&.options || {}
      config[:on_event]&.call(event)
    end

    def stripe_on_checkout_completed(ctx, event)
      config = ctx.context.options.plugins.find { |plugin| plugin.id == "stripe" }&.options || {}
      object = normalize_hash(event.dig(:data, :object) || {})
      return if object[:mode] == "setup" || !config.dig(:subscription, :enabled)

      stripe_subscription = stripe_client(config).subscriptions.retrieve(object[:subscription])
      item = stripe_subscription_item(stripe_subscription)
      return unless item

      plan = stripe_plan_by_price_info(config, stripe_fetch(stripe_fetch(item, "price") || {}, "id"), stripe_fetch(stripe_fetch(item, "price") || {}, "lookup_key"))
      metadata = normalize_hash(object[:metadata] || {})
      reference_id = object[:client_reference_id] || metadata[:reference_id]
      subscription_id = metadata[:subscription_id]
      return unless plan && reference_id && subscription_id

      update = stripe_subscription_state(stripe_subscription, include_status: true).merge(
        plan: plan[:name].to_s.downcase,
        stripeSubscriptionId: object[:subscription],
        seats: stripe_fetch(item, "quantity"),
        trialStart: stripe_time(stripe_fetch(stripe_subscription, "trial_start")),
        trialEnd: stripe_time(stripe_fetch(stripe_subscription, "trial_end"))
      ).compact
      db_subscription = ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription_id}], update: update)
      callback = config.dig(:subscription, :on_subscription_complete)
      callback&.call({event: event, subscription: db_subscription, stripeSubscription: stripe_subscription, stripe_subscription: stripe_subscription, plan: plan}, ctx)
    end

    def stripe_on_subscription_created(ctx, event)
      config = ctx.context.options.plugins.find { |plugin| plugin.id == "stripe" }&.options || {}
      object = normalize_hash(event.dig(:data, :object) || {})
      customer_id = object[:customer].to_s
      return if customer_id.empty?
      metadata = normalize_hash(object[:metadata] || {})
      existing = if metadata[:subscription_id]
        ctx.context.adapter.find_one(model: "subscription", where: [{field: "id", value: metadata[:subscription_id]}])
      else
        ctx.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: object[:id]}])
      end
      return if existing

      reference = stripe_reference_by_customer(ctx, config, customer_id) || ((metadata[:reference_id] && metadata[:plan]) ? {reference_id: metadata[:reference_id], customer_type: metadata[:customer_type] || "user"} : nil)
      return unless reference
      item = stripe_subscription_item(object)
      return unless item
      plan = stripe_plan_by_price_info(config, stripe_fetch(stripe_fetch(item, "price") || {}, "id"), stripe_fetch(stripe_fetch(item, "price") || {}, "lookup_key")) || (metadata[:plan] && stripe_plan_by_name(config, metadata[:plan]))
      return unless plan

      created = ctx.context.adapter.create(
        model: "subscription",
        data: stripe_subscription_state(object, include_status: true).merge(
          referenceId: reference.fetch(:reference_id),
          stripeCustomerId: customer_id,
          stripeSubscriptionId: object[:id],
          plan: plan[:name].to_s.downcase,
          seats: stripe_fetch(item, "quantity"),
          limits: plan[:limits]
        ).compact
      )
      config.dig(:subscription, :on_subscription_created)&.call({event: event, subscription: created, stripeSubscription: object, stripe_subscription: object, plan: plan})
    end

    def stripe_on_subscription_updated(ctx, event)
      config = ctx.context.options.plugins.find { |plugin| plugin.id == "stripe" }&.options || {}
      object = normalize_hash(event.dig(:data, :object) || {})
      item = stripe_subscription_item(object)
      return unless item

      metadata = normalize_hash(object[:metadata] || {})
      subscription = if metadata[:subscription_id]
        ctx.context.adapter.find_one(model: "subscription", where: [{field: "id", value: metadata[:subscription_id]}])
      else
        ctx.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: object[:id]}])
      end
      unless subscription
        candidates = ctx.context.adapter.find_many(model: "subscription", where: [{field: "stripeCustomerId", value: object[:customer]}])
        subscription = if candidates.length > 1
          candidates.find { |entry| stripe_active_or_trialing?(entry) }
        else
          candidates.first
        end
      end
      return unless subscription

      plan = stripe_plan_by_price_info(config, stripe_fetch(stripe_fetch(item, "price") || {}, "id"), stripe_fetch(stripe_fetch(item, "price") || {}, "lookup_key"))
      was_pending = stripe_pending_cancel?(subscription)
      update = stripe_subscription_state(object, include_status: true).merge(
        stripeSubscriptionId: object[:id],
        seats: stripe_fetch(item, "quantity")
      )
      update[:plan] = plan[:name].to_s.downcase if plan
      update[:limits] = plan[:limits] if plan&.key?(:limits)
      updated = ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: update.compact)
      if object[:status] == "active" && stripe_stripe_pending_cancel?(object) && !was_pending
        config.dig(:subscription, :on_subscription_cancel)&.call({event: event, subscription: subscription, stripeSubscription: object, stripe_subscription: object, cancellationDetails: object[:cancellation_details], cancellation_details: object[:cancellation_details]})
      end
      config.dig(:subscription, :on_subscription_update)&.call({event: event, subscription: updated || subscription})
    end

    def stripe_on_subscription_deleted(ctx, event)
      config = ctx.context.options.plugins.find { |plugin| plugin.id == "stripe" }&.options || {}
      object = normalize_hash(event.dig(:data, :object) || {})
      subscription = ctx.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: object[:id]}])
      return unless subscription

      ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: stripe_subscription_state(object, include_status: false).merge(status: "canceled"))
      config.dig(:subscription, :on_subscription_deleted)&.call({event: event, subscription: subscription, stripeSubscription: object, stripe_subscription: object})
    end

    def stripe_create_customer(config, ctx, user, metadata = nil)
      customer = stripe_find_or_create_user_customer(config, user, metadata)
      id = stripe_id(customer)
      ctx.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: id)
      id
    end

    def stripe_find_or_create_user_customer(config, user, metadata = nil)
      existing = stripe_client(config).customers.search(query: "email:\"#{stripe_escape_search(user["email"])}\" AND -metadata[\"customerType\"]:\"organization\"", limit: 1)
      customer = Array(stripe_fetch(existing, "data")).first
      return customer if customer

      extra = config[:get_customer_create_params]&.call(user, nil) || {}
      params = stripe_deep_merge(
        extra,
        email: user["email"],
        name: user["name"],
        metadata: stripe_metadata({userId: user["id"], customerType: "user"}, metadata, extra[:metadata])
      )
      stripe_client(config).customers.create(params)
    end

    def stripe_organization_customer(config, ctx, organization_id, metadata = nil)
      raise APIError.new("BAD_REQUEST", message: "Organization integration requires the organization plugin") unless config.dig(:organization, :enabled)

      org = ctx.context.adapter.find_one(model: "organization", where: [{field: "id", value: organization_id}])
      raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("ORGANIZATION_NOT_FOUND")) unless org
      return org["stripeCustomerId"] if org["stripeCustomerId"]

      existing = stripe_client(config).customers.search(query: "metadata[\"organizationId\"]:\"#{stripe_escape_search(org["id"])}\"", limit: 1)
      customer = Array(stripe_fetch(existing, "data")).first
      unless customer
        extra = config.dig(:organization, :get_customer_create_params)&.call(org, ctx) || {}
        params = stripe_deep_merge(
          extra,
          name: org["name"],
          metadata: stripe_metadata({organizationId: org["id"], customerType: "organization"}, metadata, extra[:metadata])
        )
        customer = stripe_client(config).customers.create(params)
        config.dig(:organization, :on_customer_create)&.call({stripeCustomer: customer, stripe_customer: customer, organization: org.merge("stripeCustomerId" => stripe_id(customer))}, ctx)
      end
      ctx.context.adapter.update(model: "organization", where: [{field: "id", value: org.fetch("id")}], update: {stripeCustomerId: stripe_id(customer)})
      stripe_id(customer)
    rescue APIError
      raise
    rescue
      raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("UNABLE_TO_CREATE_CUSTOMER"))
    end

    def stripe_client(config)
      config[:stripe_client] || config[:client] || raise(APIError.new("INTERNAL_SERVER_ERROR", message: "Stripe client is required"))
    end

    def stripe_id(object)
      stripe_fetch(object, "id")
    end

    def stripe_fetch(object, key)
      return nil unless object.respond_to?(:[])

      object[key] || object[key.to_sym]
    end

    def stripe_time(value)
      return nil unless value

      Time.at(value.to_i)
    end

    def stripe_subscription_options(config)
      normalize_hash(config[:subscription] || {})
    end

    def stripe_plans(config)
      plans = stripe_subscription_options(config)[:plans] || []
      plans = plans.call if plans.respond_to?(:call)
      Array(plans).map { |plan| normalize_hash(plan) }
    end

    def stripe_plan_by_name(config, name)
      stripe_plans(config).find { |plan| plan[:name].to_s.downcase == name.to_s.downcase }
    end

    def stripe_plan_by_price_info(config, price_id, lookup_key = nil)
      stripe_plans(config).find do |plan|
        plan[:price_id] == price_id || plan[:annual_discount_price_id] == price_id || (lookup_key && (plan[:lookup_key] == lookup_key || plan[:annual_discount_lookup_key] == lookup_key))
      end
    end

    def stripe_price_id(config, plan, annual = false)
      annual ? (plan[:annual_discount_price_id] || stripe_resolve_lookup(config, plan[:annual_discount_lookup_key])) : (plan[:price_id] || stripe_resolve_lookup(config, plan[:lookup_key]))
    end

    def stripe_resolve_lookup(config, lookup_key)
      return nil if lookup_key.to_s.empty?
      return nil unless stripe_client(config).respond_to?(:prices)

      prices = stripe_client(config).prices.list(lookup_keys: [lookup_key], active: true, limit: 1)
      stripe_fetch(Array(stripe_fetch(prices, "data")).first || {}, "id")
    end

    def stripe_reference_id!(ctx, session, customer_type, explicit_reference_id, config)
      return explicit_reference_id || session.fetch(:user).fetch("id") unless customer_type == "organization"
      raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("ORGANIZATION_SUBSCRIPTION_NOT_ENABLED")) unless config.dig(:organization, :enabled)

      reference_id = explicit_reference_id || session.fetch(:session)["activeOrganizationId"]
      raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("ORGANIZATION_NOT_FOUND")) if reference_id.to_s.empty?
      reference_id
    end

    def stripe_authorize_reference!(ctx, session, reference_id, action, customer_type, subscription_options, explicit: false)
      callback = subscription_options[:authorize_reference]
      if customer_type == "organization"
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("AUTHORIZE_REFERENCE_REQUIRED")) unless callback
      elsif !explicit || reference_id == session.fetch(:user).fetch("id")
        return
      elsif !callback
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("REFERENCE_ID_NOT_ALLOWED"))
      end

      allowed = callback.call({user: session.fetch(:user), session: session.fetch(:session), referenceId: reference_id, reference_id: reference_id, action: action}, ctx)
      raise APIError.new("UNAUTHORIZED", message: STRIPE_ERROR_CODES.fetch("UNAUTHORIZED")) unless allowed
    end

    def stripe_find_subscription_for_action(ctx, reference_id, subscription_id, active_only:)
      subscription = if subscription_id
        ctx.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: subscription_id}])
      else
        ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}]).find { |entry| !active_only || stripe_active_or_trialing?(entry) }
      end
      return nil if subscription_id && subscription && subscription["referenceId"] != reference_id

      subscription
    end

    def stripe_active_subscription(ctx, reference_id)
      ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}]).find { |entry| stripe_active_or_trialing?(entry) }
    end

    def stripe_active_subscriptions(config, customer_id)
      result = stripe_client(config).subscriptions.list(customer: customer_id)
      Array(stripe_fetch(result, "data")).select { |entry| stripe_active_or_trialing?(entry) }
    end

    def stripe_active_or_trialing?(subscription)
      %w[active trialing].include?(stripe_fetch(subscription, "status").to_s)
    end

    def stripe_pending_cancel?(subscription)
      !!(stripe_fetch(subscription, "cancelAtPeriodEnd") || stripe_fetch(subscription, "cancelAt"))
    end

    def stripe_stripe_pending_cancel?(subscription)
      !!(stripe_fetch(subscription, "cancel_at_period_end") || stripe_fetch(subscription, "cancel_at"))
    end

    def stripe_subscription_item(subscription)
      Array(stripe_fetch(stripe_fetch(subscription, "items") || {}, "data")).first
    end

    def stripe_subscription_state(subscription, include_status: true)
      item = stripe_subscription_item(subscription)
      state = {
        periodStart: stripe_time(stripe_fetch(item || subscription, "current_period_start")),
        periodEnd: stripe_time(stripe_fetch(item || subscription, "current_period_end")),
        cancelAtPeriodEnd: stripe_fetch(subscription, "cancel_at_period_end"),
        cancelAt: stripe_time(stripe_fetch(subscription, "cancel_at")),
        canceledAt: stripe_time(stripe_fetch(subscription, "canceled_at")),
        endedAt: stripe_time(stripe_fetch(subscription, "ended_at")),
        trialStart: stripe_time(stripe_fetch(subscription, "trial_start")),
        trialEnd: stripe_time(stripe_fetch(subscription, "trial_end"))
      }
      state[:status] = stripe_fetch(subscription, "status") if include_status
      state.compact
    end

    def stripe_reference_by_customer(ctx, config, customer_id)
      if config.dig(:organization, :enabled)
        org = ctx.context.adapter.find_one(model: "organization", where: [{field: "stripeCustomerId", value: customer_id}])
        return {customer_type: "organization", reference_id: org.fetch("id")} if org
      end
      user = ctx.context.adapter.find_one(model: "user", where: [{field: "stripeCustomerId", value: customer_id}])
      return {customer_type: "user", reference_id: user.fetch("id")} if user

      nil
    end

    def stripe_metadata(internal, *user_metadata)
      user_metadata.compact
        .reduce({}) { |acc, entry| acc.merge(normalize_hash(entry).transform_keys { |key| key.to_s }) }
        .merge(internal.transform_keys { |key| key.to_s })
    end

    def stripe_deep_merge(base, override)
      normalize_hash(base).merge(normalize_hash(override)) do |_key, old, new|
        if old.is_a?(Hash) && new.is_a?(Hash)
          stripe_deep_merge(old, new)
        else
          new
        end
      end
    end

    def stripe_redirect?(body)
      body[:disable_redirect] != true
    end

    def stripe_stringify_keys(value)
      return value unless value.is_a?(Hash)

      value.each_with_object({}) do |(key, object), result|
        result[key.to_s] = object
        result[key.to_sym] = object
      end
    end

    def stripe_url(ctx, url)
      return url if url.to_s.match?(/\A[a-zA-Z][a-zA-Z0-9+\-.]*:/)

      "#{ctx.context.base_url}#{url.to_s.start_with?("/") ? url : "/#{url}"}"
    end

    def stripe_escape_search(value)
      value.to_s.gsub("\"", "\\\"")
    end
  end
end
