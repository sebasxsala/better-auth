# frozen_string_literal: true

require "securerandom"

module BetterAuth
  module Plugins
    singleton_class.remove_method(:stripe) if singleton_class.method_defined?(:stripe)
    remove_method(:stripe) if method_defined?(:stripe) || private_method_defined?(:stripe)
    remove_const(:STRIPE_ERROR_CODES) if const_defined?(:STRIPE_ERROR_CODES, false)

    module_function

    STRIPE_ERROR_CODES = BetterAuth::Stripe::ERROR_CODES
    STRIPE_UNSAFE_METADATA_KEYS = BetterAuth::Stripe::Metadata::UNSAFE_KEYS

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
            billingInterval: {type: "string", required: false},
            stripeScheduleId: {type: "string", required: false},
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
            before: lambda do |data, hook_ctx|
              next unless data["email"] && !data["stripeCustomerId"]

              data["id"] ||= SecureRandom.hex(16)
              customer = stripe_find_or_create_user_customer(config, data, nil, hook_ctx)
              {data: {id: data["id"], stripeCustomerId: stripe_id(customer)}}
            rescue
              nil
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
        end,
        after_add_member: ->(data, ctx) { stripe_sync_organization_seats(config, data, ctx) },
        after_remove_member: ->(data, ctx) { stripe_sync_organization_seats(config, data, ctx) },
        after_accept_invitation: ->(data, ctx) { stripe_sync_organization_seats(config, data, ctx) }
      }
    end

    def stripe_upgrade_subscription_endpoint(config)
      Endpoint.new(path: "/subscription/upgrade", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        subscription_options = stripe_subscription_options(config)
        customer_type = stripe_customer_type!(body)
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

        subscriptions = subscription_to_update ? [subscription_to_update] : ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}])
        reference_customer_id = subscriptions.find { |entry| entry["stripeCustomerId"] }&.fetch("stripeCustomerId", nil)
        customer_id = if customer_type == "organization"
          subscription_to_update&.fetch("stripeCustomerId", nil) || reference_customer_id || stripe_organization_customer(config, ctx, reference_id, body[:metadata])
        else
          subscription_to_update&.fetch("stripeCustomerId", nil) || reference_customer_id || user["stripeCustomerId"] || stripe_create_customer(config, ctx, user, body[:metadata])
        end

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
        raise APIError.new("BAD_REQUEST", message: "Price ID not found for the selected plan") if price_id.to_s.empty?
        auto_managed_seats = !!(plan[:seat_price_id] && customer_type == "organization")
        member_count = auto_managed_seats ? ctx.context.adapter.count(model: "member", where: [{field: "organizationId", value: reference_id}]) : 0
        requested_seats = auto_managed_seats ? member_count : (body[:seats] || 1)
        seat_only_plan = auto_managed_seats && plan[:seat_price_id] == price_id

        active_resolved = active_stripe && stripe_resolve_plan_item(config, active_stripe)
        active_stripe_item = active_resolved&.fetch(:item, nil) || stripe_subscription_item(active_stripe || {})
        stripe_price_id_value = stripe_fetch(stripe_fetch(active_stripe_item || {}, "price") || {}, "id")
        same_plan = active_or_trialing && active_or_trialing["plan"].to_s.downcase == body[:plan].to_s.downcase
        same_seats = auto_managed_seats || (active_or_trialing && active_or_trialing["seats"].to_i == requested_seats.to_i)
        same_price = !active_stripe || stripe_price_id_value == price_id
        valid_period = !active_or_trialing || !active_or_trialing["periodEnd"] || active_or_trialing["periodEnd"] > Time.now
        if active_or_trialing&.fetch("status", nil) == "active" && same_plan && same_seats && same_price && valid_period
          raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("ALREADY_SUBSCRIBED_PLAN"))
        end

        if active_stripe
          stripe_release_plugin_schedule(ctx, config, customer_id, active_stripe, active_or_trialing || subscription_to_update)

          if body[:schedule_at_period_end]
            url = stripe_schedule_plan_change(ctx, config, active_stripe, active_or_trialing, plan, price_id, requested_seats, seat_only_plan, body)
            next ctx.json({url: url, redirect: stripe_redirect?(body)})
          end

          old_plan = active_or_trialing && stripe_plan_by_name(config, active_or_trialing["plan"])
          if stripe_direct_subscription_update?(old_plan, plan, auto_managed_seats)
            url = stripe_update_active_subscription_items(ctx, config, active_stripe, active_or_trialing, old_plan, plan, price_id, requested_seats, seat_only_plan, body)
            next ctx.json({url: url, redirect: stripe_redirect?(body)})
          end

          portal = stripe_client(config).billing_portal.sessions.create(
            customer: customer_id,
            return_url: stripe_url(ctx, body[:return_url] || "/"),
            flow_data: {
              type: "subscription_update_confirm",
              after_completion: {type: "redirect", redirect: {return_url: stripe_url(ctx, body[:return_url] || "/")}},
              subscription_update_confirm: {
                subscription: stripe_fetch(active_stripe, "id"),
                items: [stripe_line_item(config, price_id, requested_seats).merge(id: stripe_fetch(active_stripe_item || {}, "id"))]
              }
            }
          )
          next ctx.json(stripe_stringify_keys(portal).merge(redirect: stripe_redirect?(body)))
        end

        incomplete = subscriptions.find { |entry| entry["status"] == "incomplete" }
        subscription = active_or_trialing || incomplete
        if subscription
          update = {plan: plan[:name].to_s.downcase, seats: requested_seats}
          subscription = ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: update) || subscription.merge(update.transform_keys { |key| Schema.storage_key(key) })
        else
          subscription = ctx.context.adapter.create(
            model: "subscription",
            data: {plan: plan[:name].to_s.downcase, referenceId: reference_id, stripeCustomerId: customer_id, status: "incomplete", seats: requested_seats, limits: plan[:limits]}
          )
        end

        has_ever_trialed = ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}]).any? do |entry|
          entry["trialStart"] || entry["trialEnd"] || entry["status"] == "trialing"
        end
        free_trial = (!has_ever_trialed && plan[:free_trial]) ? {trial_period_days: plan.dig(:free_trial, :days)} : {}
        checkout_customization = subscription_options[:get_checkout_session_params]&.call(
          {user: user, session: session.fetch(:session), plan: plan, subscription: subscription},
          ctx.request,
          ctx
        ) || {}
        custom_params = stripe_fetch(checkout_customization, "params") || {}
        custom_options = normalize_hash(stripe_fetch(checkout_customization, "options") || {})
        custom_subscription_data = stripe_fetch(custom_params, "subscription_data") || stripe_fetch(custom_params, "subscriptionData") || {}
        internal_metadata = {userId: user.fetch("id"), subscriptionId: subscription.fetch("id"), referenceId: reference_id}
        metadata = stripe_subscription_metadata_set(internal_metadata, body[:metadata], stripe_fetch(custom_params, "metadata"))
        subscription_metadata = stripe_subscription_metadata_set(internal_metadata, body[:metadata], stripe_fetch(custom_subscription_data, "metadata"))
        checkout_params = stripe_deep_merge(
          custom_params,
          customer: customer_id,
          customer_update: (customer_type == "user") ? {name: "auto", address: "auto"} : {address: "auto"},
          locale: body[:locale],
          success_url: stripe_url(ctx, "#{ctx.context.base_url}/subscription/success?callbackURL=#{Rack::Utils.escape(body[:success_url] || "/")}&checkoutSessionId={CHECKOUT_SESSION_ID}"),
          cancel_url: stripe_url(ctx, body[:cancel_url] || "/"),
          line_items: stripe_checkout_line_items(config, plan, price_id, requested_seats, auto_managed_seats, seat_only_plan),
          subscription_data: free_trial.merge(metadata: subscription_metadata),
          mode: "subscription",
          client_reference_id: reference_id,
          metadata: metadata
        )
        checkout_params[:metadata] = metadata
        checkout_params[:subscription_data] ||= {}
        checkout_params[:subscription_data][:metadata] = subscription_metadata
        checkout = stripe_client(config).checkout.sessions.create(checkout_params, custom_options.empty? ? nil : custom_options)
        ctx.json(stripe_stringify_keys(checkout).merge(redirect: stripe_redirect?(body)))
      end
    end

    def stripe_cancel_subscription_endpoint(config)
      Endpoint.new(path: "/subscription/cancel", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        customer_type = stripe_customer_type!(body)
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
        customer_type = stripe_customer_type!(body)
        reference_id = stripe_reference_id!(ctx, session, customer_type, body[:reference_id], config)
        stripe_authorize_reference!(ctx, session, reference_id, "restore-subscription", customer_type, stripe_subscription_options(config), explicit: body.key?(:reference_id))
        subscription = stripe_find_subscription_for_action(ctx, reference_id, body[:subscription_id], active_only: false)
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")) unless subscription && subscription["stripeCustomerId"]
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_ACTIVE")) unless stripe_active_or_trialing?(subscription)

        if subscription["stripeScheduleId"]
          schedule = stripe_client(config).subscription_schedules.retrieve(subscription["stripeScheduleId"])
          if stripe_fetch(schedule, "status") == "active"
            schedule = stripe_client(config).subscription_schedules.release(subscription["stripeScheduleId"])
          end
          ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {stripeScheduleId: nil})
          next ctx.json(stripe_stringify_keys(schedule))
        end

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
        customer_type = stripe_customer_type!(query)
        reference_id = stripe_reference_id!(ctx, session, customer_type, query[:reference_id], config)
        stripe_authorize_reference!(ctx, session, reference_id, "list-subscription", customer_type, stripe_subscription_options(config), explicit: query.key?(:reference_id))
        plans = stripe_plans(config)
        subscriptions = ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: reference_id}]).select { |entry| stripe_active_or_trialing?(entry) }
        ctx.json(subscriptions.map do |entry|
          plan = plans.find { |item| item[:name].to_s.downcase == entry["plan"].to_s.downcase }
          price_id = if entry["billingInterval"] == "year"
            plan&.fetch(:annual_discount_price_id, nil) || plan&.fetch(:price_id, nil)
          else
            plan&.fetch(:price_id, nil)
          end
          entry.merge("limits" => plan&.fetch(:limits, nil), "priceId" => price_id)
        end)
      end
    end

    def stripe_billing_portal_endpoint(config)
      Endpoint.new(path: "/subscription/billing-portal", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        customer_type = stripe_customer_type!(body)
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
        checkout_session_id = query[:checkout_session_id]
        subscription_id = query[:subscription_id]
        if checkout_session_id
          callback = callback.to_s.gsub("{CHECKOUT_SESSION_ID}", checkout_session_id.to_s)
          checkout_session = begin
            stripe_client(config || {}).checkout.sessions.retrieve(checkout_session_id)
          rescue
            nil
          end
          raise ctx.redirect(stripe_url(ctx, callback)) unless checkout_session

          metadata = normalize_hash(stripe_fetch(checkout_session || {}, "metadata") || {})
          subscription_id = metadata[:subscription_id]
        end

        unless subscription_id
          raise ctx.redirect(stripe_url(ctx, callback))
        end
        session = Routes.current_session(ctx, allow_nil: true)
        raise ctx.redirect(stripe_url(ctx, callback)) unless session

        subscription = ctx.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription_id}])
        raise ctx.redirect(stripe_url(ctx, callback)) unless subscription
        raise ctx.redirect(stripe_url(ctx, callback)) if stripe_active_or_trialing?(subscription)

        customer_id = subscription["stripeCustomerId"] || session.fetch(:user)["stripeCustomerId"]
        raise ctx.redirect(stripe_url(ctx, callback)) unless customer_id

        stripe_subscription = stripe_active_subscriptions(config || {}, customer_id).first
        if stripe_subscription
          resolved = stripe_resolve_plan_item(config || {}, stripe_subscription)
          item = resolved&.fetch(:item, nil)
          plan = resolved&.fetch(:plan, nil)
          if item && plan
            ctx.context.adapter.update(
              model: "subscription",
              where: [{field: "id", value: subscription.fetch("id")}],
              update: stripe_subscription_state(stripe_subscription, include_status: true, compact: false).merge(
                plan: plan[:name].to_s.downcase,
                seats: stripe_resolve_quantity(stripe_subscription, item, plan),
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

        event = begin
          if stripe_client(config).respond_to?(:webhooks)
            webhooks = stripe_client(config).webhooks
            if webhooks.respond_to?(:construct_event_async)
              webhooks.construct_event_async(ctx.body, signature, config[:stripe_webhook_secret])
            else
              webhooks.construct_event(ctx.body, signature, config[:stripe_webhook_secret])
            end
          else
            ctx.body
          end
        rescue
          raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT"))
        end
        raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT")) unless event
        begin
          stripe_handle_event(ctx, event)
        rescue
          raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("STRIPE_WEBHOOK_ERROR"))
        end
        ctx.json({success: true})
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
      resolved = stripe_resolve_plan_item(config, stripe_subscription)
      return unless resolved

      item = resolved.fetch(:item)
      plan = resolved.fetch(:plan)
      metadata = normalize_hash(object[:metadata] || {})
      reference_id = object[:client_reference_id] || metadata[:reference_id]
      subscription_id = metadata[:subscription_id]
      return unless plan && reference_id && subscription_id

      update = stripe_subscription_state(stripe_subscription, include_status: true).merge(
        plan: plan[:name].to_s.downcase,
        stripeSubscriptionId: object[:subscription],
        seats: stripe_resolve_quantity(stripe_subscription, item, plan),
        trialStart: stripe_time(stripe_fetch(stripe_subscription, "trial_start")),
        trialEnd: stripe_time(stripe_fetch(stripe_subscription, "trial_end"))
      ).compact
      db_subscription = ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription_id}], update: update)
      plan.dig(:free_trial, :on_trial_start)&.call(db_subscription) if db_subscription && update[:trialStart]
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
      resolved = stripe_resolve_plan_item(config, object)
      return unless resolved
      item = resolved.fetch(:item)
      plan = resolved[:plan] || (metadata[:plan] && stripe_plan_by_name(config, metadata[:plan]))
      return unless plan

      created = ctx.context.adapter.create(
        model: "subscription",
        data: stripe_subscription_state(object, include_status: true).merge(
          referenceId: reference.fetch(:reference_id),
          stripeCustomerId: customer_id,
          stripeSubscriptionId: object[:id],
          plan: plan[:name].to_s.downcase,
          seats: stripe_resolve_quantity(object, item, plan),
          limits: plan[:limits]
        ).compact
      )
      config.dig(:subscription, :on_subscription_created)&.call({event: event, subscription: created, stripeSubscription: object, stripe_subscription: object, plan: plan})
    end

    def stripe_on_subscription_updated(ctx, event)
      config = ctx.context.options.plugins.find { |plugin| plugin.id == "stripe" }&.options || {}
      object = normalize_hash(event.dig(:data, :object) || {})
      resolved = stripe_resolve_plan_item(config, object)
      return unless resolved
      item = resolved.fetch(:item)

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

      plan = resolved[:plan]
      was_pending = stripe_pending_cancel?(subscription)
      update = stripe_subscription_state(object, include_status: true, compact: false).merge(
        stripeSubscriptionId: object[:id],
        seats: stripe_resolve_quantity(object, item, plan)
      )
      update[:plan] = plan[:name].to_s.downcase if plan
      update[:limits] = plan[:limits] if plan&.key?(:limits)
      updated = ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: update)
      if object[:status] == "active" && stripe_stripe_pending_cancel?(object) && !was_pending
        config.dig(:subscription, :on_subscription_cancel)&.call({event: event, subscription: subscription, stripeSubscription: object, stripe_subscription: object, cancellationDetails: object[:cancellation_details], cancellation_details: object[:cancellation_details]})
      end
      config.dig(:subscription, :on_subscription_update)&.call({event: event, subscription: updated || subscription})
      if plan && subscription["status"] == "trialing" && object[:status] == "active"
        plan.dig(:free_trial, :on_trial_end)&.call({subscription: subscription}, ctx)
      end
      if plan && subscription["status"] == "trialing" && object[:status] == "incomplete_expired"
        plan.dig(:free_trial, :on_trial_expired)&.call(subscription, ctx)
      end
    end

    def stripe_on_subscription_deleted(ctx, event)
      config = ctx.context.options.plugins.find { |plugin| plugin.id == "stripe" }&.options || {}
      object = normalize_hash(event.dig(:data, :object) || {})
      subscription = ctx.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: object[:id]}])
      return unless subscription

      ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: stripe_subscription_state(object, include_status: false, compact: false).merge(status: "canceled", stripeScheduleId: nil))
      config.dig(:subscription, :on_subscription_deleted)&.call({event: event, subscription: subscription, stripeSubscription: object, stripe_subscription: object})
    end

    def stripe_create_customer(config, ctx, user, metadata = nil)
      customer = stripe_find_or_create_user_customer(config, user, metadata, ctx)
      id = stripe_id(customer)
      ctx.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: id)
      id
    end

    def stripe_find_or_create_user_customer(config, user, metadata = nil, ctx = nil)
      customer = stripe_find_user_customer(config, user["email"])
      if customer
        stripe_notify_customer_created(config, customer, user, ctx)
        return customer
      end

      raw_extra = config[:get_customer_create_params]&.call(user, ctx) || {}
      extra_metadata = stripe_fetch(raw_extra, "metadata")
      extra = normalize_hash(raw_extra)
      params = stripe_deep_merge(
        extra,
        email: user["email"],
        name: user["name"],
        metadata: stripe_customer_metadata_set({userId: user["id"], customerType: "user"}, metadata, extra_metadata)
      )
      params[:metadata] = stripe_customer_metadata_set({userId: user["id"], customerType: "user"}, metadata, extra_metadata)
      customer = stripe_client(config).customers.create(params)
      stripe_notify_customer_created(config, customer, user, ctx)
      customer
    end

    def stripe_organization_customer(config, ctx, organization_id, metadata = nil)
      raise APIError.new("BAD_REQUEST", message: "Organization integration requires the organization plugin") unless config.dig(:organization, :enabled)

      org = ctx.context.adapter.find_one(model: "organization", where: [{field: "id", value: organization_id}])
      raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("ORGANIZATION_NOT_FOUND")) unless org
      return org["stripeCustomerId"] if org["stripeCustomerId"]

      customer = stripe_find_organization_customer(config, org["id"])
      unless customer
        raw_extra = config.dig(:organization, :get_customer_create_params)&.call(org, ctx) || {}
        extra_metadata = stripe_fetch(raw_extra, "metadata")
        extra = normalize_hash(raw_extra)
        params = stripe_deep_merge(
          extra,
          name: org["name"],
          metadata: stripe_customer_metadata_set({organizationId: org["id"], customerType: "organization"}, metadata, extra_metadata)
        )
        params[:metadata] = stripe_customer_metadata_set({organizationId: org["id"], customerType: "organization"}, metadata, extra_metadata)
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
      injected = config[:stripe_client] || config[:client]
      return injected if injected
      return config[:_stripe_client_adapter] if config[:_stripe_client_adapter]

      api_key = config[:stripe_api_key] || ENV["STRIPE_SECRET_KEY"]
      raise APIError.new("INTERNAL_SERVER_ERROR", message: "Stripe client is required") if api_key.to_s.empty?

      config[:_stripe_client_adapter] = BetterAuth::Stripe::ClientAdapter.new(api_key)
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
      Array(plans).map do |plan|
        normalized = normalize_hash(plan)
        limits = stripe_fetch(plan, "limits")
        normalized[:limits] = limits if limits
        normalized
      end
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
      raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("ORGANIZATION_REFERENCE_ID_REQUIRED")) if reference_id.to_s.empty?
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

    def stripe_customer_type!(source)
      customer_type = (source[:customer_type] || "user").to_s
      raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("INVALID_CUSTOMER_TYPE")) unless %w[user organization].include?(customer_type)

      customer_type
    end

    def stripe_find_user_customer(config, email)
      customers = stripe_client(config).customers
      begin
        existing = customers.search(query: "email:\"#{stripe_escape_search(email)}\" AND -metadata[\"customerType\"]:\"organization\"", limit: 1)
        Array(stripe_fetch(existing, "data")).first
      rescue
        listed = customers.list(email: email, limit: 100)
        Array(stripe_fetch(listed, "data")).find do |customer|
          stripe_metadata_fetch(stripe_fetch(customer, "metadata") || {}, "customerType") != "organization"
        end
      end
    end

    def stripe_find_organization_customer(config, organization_id)
      customers = stripe_client(config).customers
      begin
        existing = customers.search(query: "metadata[\"organizationId\"]:\"#{stripe_escape_search(organization_id)}\" AND metadata[\"customerType\"]:\"organization\"", limit: 1)
        Array(stripe_fetch(existing, "data")).first
      rescue
        listed = customers.list(limit: 100)
        Array(stripe_fetch(listed, "data")).find do |customer|
          metadata = stripe_fetch(customer, "metadata") || {}
          stripe_metadata_fetch(metadata, "organizationId") == organization_id &&
            stripe_metadata_fetch(metadata, "customerType") == "organization"
        end
      end
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

    def stripe_resolve_plan_item(config, subscription)
      items = Array(stripe_fetch(stripe_fetch(subscription, "items") || {}, "data"))
      first = items.first
      return nil unless first

      items.each do |item|
        price = stripe_fetch(item, "price") || {}
        plan = stripe_plan_by_price_info(config, stripe_fetch(price, "id"), stripe_fetch(price, "lookup_key"))
        return {item: item, plan: plan} if plan
      end
      {item: first, plan: nil} if items.length == 1
    end

    def stripe_resolve_quantity(subscription, plan_item, plan = nil)
      items = Array(stripe_fetch(stripe_fetch(subscription, "items") || {}, "data"))
      seat_price_id = plan && plan[:seat_price_id]
      seat_item = seat_price_id && items.find { |item| stripe_fetch(stripe_fetch(item, "price") || {}, "id") == seat_price_id }
      stripe_fetch(seat_item || plan_item, "quantity") || 1
    end

    def stripe_line_item(config, price_id, quantity)
      item = {price: price_id}
      item[:quantity] = quantity unless stripe_metered_price?(config, price_id)
      item
    end

    def stripe_checkout_line_items(config, plan, price_id, quantity, auto_managed_seats, seat_only_plan)
      items = []
      items << stripe_line_item(config, price_id, auto_managed_seats ? 1 : quantity) unless seat_only_plan
      items << {price: plan[:seat_price_id], quantity: quantity} if auto_managed_seats && plan[:seat_price_id]
      items.concat(stripe_plan_line_items(plan))
      items
    end

    def stripe_plan_line_items(plan)
      Array(plan[:line_items]).map do |item|
        item.is_a?(Hash) ? normalize_hash(item) : item
      end
    end

    def stripe_schedule_plan_change(ctx, config, active_stripe, db_subscription, plan, price_id, quantity, seat_only_plan, body)
      schedule = stripe_client(config).subscription_schedules.create(from_subscription: stripe_fetch(active_stripe, "id"))
      current_phase = Array(stripe_fetch(schedule, "phases")).first || {}
      current_items = Array(stripe_fetch(current_phase, "items"))
      active_item = stripe_resolve_plan_item(config, active_stripe)&.fetch(:item, nil) || stripe_subscription_item(active_stripe)
      active_price_id = stripe_fetch(stripe_fetch(active_item || {}, "price") || {}, "id")
      replaced = false
      new_items = current_items.filter_map do |item|
        item_price = stripe_fetch(item, "price")
        item_price = stripe_fetch(item_price, "id") if item_price.is_a?(Hash)
        if item_price == active_price_id
          replaced = true
          next nil if seat_only_plan

          stripe_line_item(config, price_id, quantity)
        else
          {price: item_price, quantity: stripe_fetch(item, "quantity")}.compact
        end
      end
      new_items << stripe_line_item(config, price_id, quantity) unless replaced || seat_only_plan
      new_items << {price: plan[:seat_price_id], quantity: quantity} if plan[:seat_price_id]
      new_items.concat(stripe_plan_line_items(plan))

      stripe_client(config).subscription_schedules.update(
        stripe_fetch(schedule, "id"),
        metadata: {source: "@better-auth/stripe"},
        end_behavior: "release",
        phases: [
          {
            items: current_items.map do |item|
              item_price = stripe_fetch(item, "price")
              item_price = stripe_fetch(item_price, "id") if item_price.is_a?(Hash)
              {price: item_price, quantity: stripe_fetch(item, "quantity")}.compact
            end,
            start_date: stripe_fetch(current_phase, "start_date"),
            end_date: stripe_fetch(current_phase, "end_date")
          },
          {
            items: new_items,
            start_date: stripe_fetch(current_phase, "end_date"),
            proration_behavior: "none"
          }
        ]
      )
      if db_subscription
        ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: db_subscription.fetch("id")}], update: {stripeScheduleId: stripe_fetch(schedule, "id")})
      end
      stripe_url(ctx, body[:return_url] || "/")
    end

    def stripe_release_plugin_schedule(ctx, config, customer_id, active_stripe, db_subscription)
      return unless stripe_schedule_id(active_stripe)
      return unless stripe_client(config).respond_to?(:subscription_schedules)

      schedules = stripe_client(config).subscription_schedules.list(customer: customer_id)
      active_subscription_id = stripe_fetch(active_stripe, "id")
      existing = Array(stripe_fetch(schedules, "data")).find do |schedule|
        subscription = stripe_fetch(schedule, "subscription")
        schedule_subscription_id = subscription.is_a?(Hash) ? stripe_id(subscription) : subscription
        metadata = stripe_fetch(schedule, "metadata") || {}
        schedule_subscription_id == active_subscription_id &&
          stripe_fetch(schedule, "status") == "active" &&
          stripe_metadata_fetch(metadata, "source") == "@better-auth/stripe"
      end
      return unless existing

      stripe_client(config).subscription_schedules.release(stripe_id(existing))
      if db_subscription
        ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: db_subscription.fetch("id")}], update: {stripeScheduleId: nil})
      end
    end

    def stripe_direct_subscription_update?(old_plan, plan, auto_managed_seats)
      return true if auto_managed_seats && old_plan && old_plan[:seat_price_id] != plan[:seat_price_id]

      stripe_plan_line_items(old_plan || {}).map { |item| item[:price] } != stripe_plan_line_items(plan).map { |item| item[:price] }
    end

    def stripe_update_active_subscription_items(ctx, config, active_stripe, db_subscription, old_plan, plan, price_id, quantity, seat_only_plan, body)
      active_item = stripe_resolve_plan_item(config, active_stripe)&.fetch(:item, nil) || stripe_subscription_item(active_stripe)
      active_price_id = stripe_fetch(stripe_fetch(active_item || {}, "price") || {}, "id")
      old_line_prices = stripe_plan_line_items(old_plan || {}).map { |item| item[:price] }
      new_line_prices = stripe_plan_line_items(plan).map { |item| item[:price] }
      added_line_prices = new_line_prices - old_line_prices
      items = []
      Array(stripe_fetch(stripe_fetch(active_stripe, "items") || {}, "data")).each do |item|
        item_price = stripe_fetch(stripe_fetch(item, "price") || {}, "id")
        if item_price == active_price_id
          items << stripe_line_item(config, price_id, plan[:seat_price_id] ? 1 : quantity).merge(id: stripe_fetch(item, "id")) unless seat_only_plan
        elsif old_plan && item_price == old_plan[:seat_price_id] && plan[:seat_price_id]
          items << {id: stripe_fetch(item, "id"), price: plan[:seat_price_id], quantity: quantity}
        elsif old_line_prices.include?(item_price)
          if new_line_prices.include?(item_price)
            new_line_prices.delete_at(new_line_prices.index(item_price))
          else
            items << {id: stripe_fetch(item, "id"), deleted: true}
          end
        end
      end
      items << {price: plan[:seat_price_id], quantity: quantity} if plan[:seat_price_id] && !items.any? { |item| item[:price] == plan[:seat_price_id] || item[:id] && item[:price] == plan[:seat_price_id] }
      added_line_prices.each { |price| items << {price: price} }
      stripe_client(config).subscriptions.update(stripe_fetch(active_stripe, "id"), items: items, proration_behavior: plan[:proration_behavior] || "create_prorations")
      if db_subscription
        ctx.context.adapter.update(
          model: "subscription",
          where: [{field: "id", value: db_subscription.fetch("id")}],
          update: {plan: plan[:name].to_s.downcase, seats: quantity, limits: plan[:limits], stripeScheduleId: nil}
        )
      end
      stripe_url(ctx, body[:return_url] || "/")
    end

    def stripe_sync_organization_seats(config, data, ctx)
      organization = data[:organization] || data["organization"]
      return unless config.dig(:subscription, :enabled) && organization && organization["stripeCustomerId"]

      member_count = ctx.context.adapter.count(model: "member", where: [{field: "organizationId", value: organization.fetch("id")}])
      seat_plans = stripe_plans(config).select { |plan| plan[:seat_price_id] }
      return if seat_plans.empty?

      subscription = ctx.context.adapter.find_many(model: "subscription", where: [{field: "referenceId", value: organization.fetch("id")}]).find { |entry| stripe_active_or_trialing?(entry) }
      return unless subscription && subscription["stripeSubscriptionId"]

      plan = seat_plans.find { |entry| entry[:name].to_s.downcase == subscription["plan"].to_s.downcase }
      return unless plan

      stripe_subscription = stripe_client(config).subscriptions.retrieve(subscription["stripeSubscriptionId"])
      return unless stripe_active_or_trialing?(stripe_subscription)

      items = Array(stripe_fetch(stripe_fetch(stripe_subscription, "items") || {}, "data"))
      seat_item = items.find { |item| stripe_fetch(stripe_fetch(item, "price") || {}, "id") == plan[:seat_price_id] }
      return if seat_item && stripe_fetch(seat_item, "quantity").to_i == member_count.to_i

      update_items = if seat_item
        [{id: stripe_fetch(seat_item, "id"), quantity: member_count}]
      else
        [{price: plan[:seat_price_id], quantity: member_count}]
      end
      stripe_client(config).subscriptions.update(subscription["stripeSubscriptionId"], items: update_items, proration_behavior: plan[:proration_behavior] || "create_prorations")
      ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {seats: member_count})
    rescue
      nil
    end

    def stripe_metered_price?(config, price_id, lookup_key = nil)
      price = stripe_resolve_stripe_price(config, price_id, lookup_key)
      recurring = stripe_fetch(price || {}, "recurring") || {}
      stripe_fetch(recurring, "usage_type") == "metered"
    end

    def stripe_resolve_stripe_price(config, price_id, lookup_key = nil)
      return nil unless stripe_client(config).respond_to?(:prices)

      prices = stripe_client(config).prices
      if lookup_key
        result = prices.list(lookup_keys: [lookup_key], active: true, limit: 1)
        Array(stripe_fetch(result, "data")).first
      elsif price_id && prices.respond_to?(:retrieve)
        prices.retrieve(price_id)
      end
    rescue
      nil
    end

    def stripe_subscription_state(subscription, include_status: true, compact: true)
      item = stripe_subscription_item(subscription)
      price = stripe_fetch(item || {}, "price") || {}
      recurring = stripe_fetch(price, "recurring") || {}
      state = {
        periodStart: stripe_time(stripe_fetch(item || subscription, "current_period_start")),
        periodEnd: stripe_time(stripe_fetch(item || subscription, "current_period_end")),
        cancelAtPeriodEnd: stripe_fetch(subscription, "cancel_at_period_end"),
        cancelAt: stripe_time(stripe_fetch(subscription, "cancel_at")),
        canceledAt: stripe_time(stripe_fetch(subscription, "canceled_at")),
        endedAt: stripe_time(stripe_fetch(subscription, "ended_at")),
        trialStart: stripe_time(stripe_fetch(subscription, "trial_start")),
        trialEnd: stripe_time(stripe_fetch(subscription, "trial_end")),
        billingInterval: stripe_fetch(recurring, "interval"),
        stripeScheduleId: stripe_schedule_id(subscription)
      }
      state[:status] = stripe_fetch(subscription, "status") if include_status
      compact ? state.compact : state
    end

    def stripe_schedule_id(subscription)
      schedule = stripe_fetch(subscription, "schedule")
      return nil if schedule.nil?
      return schedule if schedule.is_a?(String)

      stripe_id(schedule) || schedule.to_s
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
      BetterAuth::Stripe::Metadata.merge(internal, *user_metadata)
    end

    def stripe_customer_metadata_set(internal_fields, *user_metadata)
      BetterAuth::Stripe::Metadata.customer_set(internal_fields, *user_metadata)
    end

    def stripe_customer_metadata_get(metadata)
      BetterAuth::Stripe::Metadata.customer_get(metadata)
    end

    def stripe_subscription_metadata_set(internal_fields, *user_metadata)
      BetterAuth::Stripe::Metadata.subscription_set(internal_fields, *user_metadata)
    end

    def stripe_subscription_metadata_get(metadata)
      BetterAuth::Stripe::Metadata.subscription_get(metadata)
    end

    def stripe_notify_customer_created(config, customer, user, ctx)
      config[:on_customer_create]&.call(
        {
          stripeCustomer: customer,
          stripe_customer: customer,
          user: user.merge("stripeCustomerId" => stripe_id(customer))
        },
        ctx
      )
    end

    def stripe_metadata_key(key)
      BetterAuth::Stripe::Metadata.metadata_key(key)
    end

    def stripe_metadata_fetch(metadata, key)
      BetterAuth::Stripe::Metadata.metadata_fetch(metadata, key)
    end

    def stripe_deep_merge(base, override)
      BetterAuth::Stripe::Metadata.deep_merge(base, override)
    end

    def stripe_redirect?(body)
      body[:disable_redirect] != true
    end

    def stripe_stringify_keys(value)
      BetterAuth::Stripe::Metadata.stringify_keys(value)
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
