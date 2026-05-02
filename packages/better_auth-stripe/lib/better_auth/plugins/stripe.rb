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
      BetterAuth::Stripe::Schema.schema(config)
    end

    def stripe_endpoints(config)
      BetterAuth::Stripe::Routes.endpoints(config)
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
      BetterAuth::Stripe::OrganizationHooks.hooks(config)
    end

    def stripe_upgrade_subscription_endpoint(config)
      BetterAuth::Stripe::Routes::UpgradeSubscription.endpoint(config)
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
      BetterAuth::Stripe::Hooks.handle_event(ctx, event)
    end

    def stripe_on_checkout_completed(ctx, event)
      BetterAuth::Stripe::Hooks.on_checkout_completed(ctx, event)
    end

    def stripe_on_subscription_created(ctx, event)
      BetterAuth::Stripe::Hooks.on_subscription_created(ctx, event)
    end

    def stripe_on_subscription_updated(ctx, event)
      BetterAuth::Stripe::Hooks.on_subscription_updated(ctx, event)
    end

    def stripe_on_subscription_deleted(ctx, event)
      BetterAuth::Stripe::Hooks.on_subscription_deleted(ctx, event)
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
      BetterAuth::Stripe::Utils.id(object)
    end

    def stripe_fetch(object, key)
      BetterAuth::Stripe::Utils.fetch(object, key)
    end

    def stripe_time(value)
      BetterAuth::Stripe::Utils.time(value)
    end

    def stripe_subscription_options(config)
      BetterAuth::Stripe::Utils.subscription_options(config)
    end

    def stripe_plans(config)
      BetterAuth::Stripe::Utils.plans(config)
    end

    def stripe_plan_by_name(config, name)
      BetterAuth::Stripe::Utils.plan_by_name(config, name)
    end

    def stripe_plan_by_price_info(config, price_id, lookup_key = nil)
      BetterAuth::Stripe::Utils.plan_by_price_info(config, price_id, lookup_key)
    end

    def stripe_price_id(config, plan, annual = false)
      BetterAuth::Stripe::Utils.price_id(config, plan, annual)
    end

    def stripe_resolve_lookup(config, lookup_key)
      BetterAuth::Stripe::Utils.resolve_lookup(config, lookup_key)
    end

    def stripe_reference_id!(ctx, session, customer_type, explicit_reference_id, config)
      BetterAuth::Stripe::Middleware.reference_id!(ctx, session, customer_type, explicit_reference_id, config)
    end

    def stripe_authorize_reference!(ctx, session, reference_id, action, customer_type, subscription_options, explicit: false)
      BetterAuth::Stripe::Middleware.authorize_reference!(ctx, session, reference_id, action, customer_type, subscription_options, explicit: explicit)
    end

    def stripe_customer_type!(source)
      BetterAuth::Stripe::Middleware.customer_type!(source)
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
      BetterAuth::Stripe::Utils.active_or_trialing?(subscription)
    end

    def stripe_pending_cancel?(subscription)
      BetterAuth::Stripe::Utils.pending_cancel?(subscription)
    end

    def stripe_stripe_pending_cancel?(subscription)
      BetterAuth::Stripe::Utils.stripe_pending_cancel?(subscription)
    end

    def stripe_subscription_item(subscription)
      BetterAuth::Stripe::Utils.subscription_item(subscription)
    end

    def stripe_resolve_plan_item(config, subscription)
      BetterAuth::Stripe::Utils.resolve_plan_item(config, subscription)
    end

    def stripe_resolve_quantity(subscription, plan_item, plan = nil)
      BetterAuth::Stripe::Utils.resolve_quantity(subscription, plan_item, plan)
    end

    def stripe_line_item(config, price_id, quantity)
      BetterAuth::Stripe::Utils.line_item(config, price_id, quantity)
    end

    def stripe_checkout_line_items(config, plan, price_id, quantity, auto_managed_seats, seat_only_plan)
      BetterAuth::Stripe::Utils.checkout_line_items(config, plan, price_id, quantity, auto_managed_seats, seat_only_plan)
    end

    def stripe_plan_line_items(plan)
      BetterAuth::Stripe::Utils.plan_line_items(plan)
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
      BetterAuth::Stripe::Utils.direct_subscription_update?(old_plan, plan, auto_managed_seats)
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
      BetterAuth::Stripe::OrganizationHooks.sync_seats(config, data, ctx)
    end

    def stripe_metered_price?(config, price_id, lookup_key = nil)
      BetterAuth::Stripe::Utils.metered_price?(config, price_id, lookup_key)
    end

    def stripe_resolve_stripe_price(config, price_id, lookup_key = nil)
      BetterAuth::Stripe::Utils.resolve_stripe_price(config, price_id, lookup_key)
    end

    def stripe_subscription_state(subscription, include_status: true, compact: true)
      BetterAuth::Stripe::Utils.subscription_state(subscription, include_status: include_status, compact: compact)
    end

    def stripe_schedule_id(subscription)
      BetterAuth::Stripe::Utils.schedule_id(subscription)
    end

    def stripe_reference_by_customer(ctx, config, customer_id)
      BetterAuth::Stripe::Middleware.reference_by_customer(ctx, config, customer_id)
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
      BetterAuth::Stripe::Utils.redirect?(body)
    end

    def stripe_stringify_keys(value)
      BetterAuth::Stripe::Metadata.stringify_keys(value)
    end

    def stripe_url(ctx, url)
      BetterAuth::Stripe::Utils.url(ctx, url)
    end

    def stripe_escape_search(value)
      BetterAuth::Stripe::Utils.escape_search(value)
    end
  end
end
