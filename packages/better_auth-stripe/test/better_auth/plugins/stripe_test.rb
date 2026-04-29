# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsStripeTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_creates_customer_on_sign_up_and_subscription_checkout
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: true)

    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "billing@example.com", password: "password123", name: "Billing User"},
      as_response: true
    )
    cookie = cookie_header(headers.fetch("set-cookie"))
    user = auth.context.internal_adapter.find_user_by_email("billing@example.com")[:user]
    assert_match(/\Acus_/, user.fetch("stripeCustomerId"))
    assert_equal 1, stripe.customers.created.length

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "pro", successUrl: "http://localhost:3000/success", cancelUrl: "http://localhost:3000/cancel"}
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "plan", value: "pro"}])
    assert_equal user.fetch("id"), subscription.fetch("referenceId")
    assert_equal "incomplete", subscription.fetch("status")
    assert_nil subscription["stripeSubscriptionId"]
  end

  def test_metadata_helpers_protect_internal_fields_and_preserve_custom_keys
    customer = BetterAuth::Plugins.stripe_customer_metadata_set(
      {userId: "real", customerType: "user"},
      {userId: "fake", customField: "value"}
    )

    assert_equal "real", customer.fetch("userId")
    assert_equal "user", customer.fetch("customerType")
    assert_equal "value", customer.fetch("customField")
    assert_equal({userId: "real", organizationId: nil, customerType: "user"}, BetterAuth::Plugins.stripe_customer_metadata_get(customer))

    subscription = BetterAuth::Plugins.stripe_subscription_metadata_set(
      {userId: "u1", subscriptionId: "s1", referenceId: "r1"},
      {subscriptionId: "fake", customField: "value"}
    )

    assert_equal "s1", subscription.fetch("subscriptionId")
    assert_equal "value", subscription.fetch("customField")
    assert_equal({userId: "u1", subscriptionId: "s1", referenceId: "r1"}, BetterAuth::Plugins.stripe_subscription_metadata_get(subscription))
  end

  def test_metadata_helpers_drop_unsafe_keys
    customer = BetterAuth::Plugins.stripe_customer_metadata_set(
      {userId: "real", customerType: "user"},
      {"__proto__" => "polluted", "constructor" => "polluted", "prototype" => "polluted", "safe" => "kept"}
    )

    refute customer.key?("__proto__")
    refute customer.key?("constructor")
    refute customer.key?("prototype")
    assert_equal "kept", customer.fetch("safe")

    subscription = BetterAuth::Plugins.stripe_subscription_metadata_set(
      {userId: "u1", subscriptionId: "s1", referenceId: "r1"},
      {"__proto__" => "polluted", "constructor" => "polluted", "prototype" => "polluted", "safe" => "kept"}
    )

    refute subscription.key?("__proto__")
    refute subscription.key?("constructor")
    refute subscription.key?("prototype")
    assert_equal "kept", subscription.fetch("safe")
  end

  def test_subscription_schema_includes_upstream_schedule_and_interval_fields
    plugin = BetterAuth::Plugins.stripe(subscription: {enabled: true, plans: []})
    fields = plugin.schema.fetch(:subscription).fetch(:fields)

    assert_equal({type: "string", required: false}, fields.fetch(:billing_interval))
    assert_equal({type: "string", required: false}, fields.fetch(:stripe_schedule_id))
  end

  def test_customer_create_params_and_callback_receive_upstream_shape
    stripe = FakeStripeClient.new
    payloads = []
    auth = build_auth(
      stripe_client: stripe,
      create_customer_on_sign_up: true,
      get_customer_create_params: ->(user, _ctx) { {phone: "+1234567890", metadata: {customField: "customValue", userId: "fake"}} },
      on_customer_create: ->(payload, _ctx) { payloads << payload }
    )

    auth.api.sign_up_email(
      body: {email: "customer-callback@example.com", password: "password123", name: "Customer Callback"},
      as_response: true
    )

    user = auth.context.internal_adapter.find_user_by_email("customer-callback@example.com")[:user]
    created = stripe.customers.created.fetch(0)
    assert_equal "+1234567890", created.fetch(:phone)
    assert_equal "customValue", created.fetch("metadata").fetch("customField")
    assert_equal user.fetch("id"), created.fetch("metadata").fetch("userId")
    assert_equal "user", created.fetch("metadata").fetch("customerType")
    assert_equal 1, payloads.length
    assert_equal created, payloads.fetch(0).fetch(:stripeCustomer)
    assert_equal created, payloads.fetch(0).fetch(:stripe_customer)
    assert_equal created.fetch("id"), payloads.fetch(0).fetch(:user).fetch("stripeCustomerId")
  end

  def test_create_customer_on_sign_up_falls_back_to_customer_list_when_search_unavailable
    stripe = FakeStripeClient.new
    stripe.customers.search_error = RuntimeError.new("search unavailable")
    stripe.customers.list_data = [{"id" => "cus_existing", "email" => "fallback@example.com", "metadata" => {"customerType" => "user"}}]
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: true)

    auth.api.sign_up_email(
      body: {email: "fallback@example.com", password: "password123", name: "Fallback User"},
      as_response: true
    )

    user = auth.context.internal_adapter.find_user_by_email("fallback@example.com")[:user]
    assert_equal "cus_existing", user.fetch("stripeCustomerId")
    assert_empty stripe.customers.created
    assert_equal({email: "fallback@example.com", limit: 100}, stripe.customers.list_calls.fetch(0))
  end

  def test_create_customer_on_sign_up_does_not_block_sign_up_when_stripe_fails
    stripe = FakeStripeClient.new
    stripe.customers.search_error = RuntimeError.new("search unavailable")
    stripe.customers.create_error = RuntimeError.new("stripe unavailable")
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: true)

    status, = auth.api.sign_up_email(
      body: {email: "tolerant-signup@example.com", password: "password123", name: "Tolerant User"},
      as_response: true
    )

    user = auth.context.internal_adapter.find_user_by_email("tolerant-signup@example.com")[:user]
    assert_equal 200, status
    assert_equal "tolerant-signup@example.com", user.fetch("email")
    assert_nil user["stripeCustomerId"]
  end

  def test_upgrade_falls_back_to_customer_list_when_search_unavailable
    stripe = FakeStripeClient.new
    stripe.customers.search_error = RuntimeError.new("search unavailable")
    stripe.customers.list_data = [{"id" => "cus_upgrade_existing", "email" => "fallback-upgrade@example.com", "metadata" => {"customerType" => "user"}}]
    auth = build_auth(stripe_client: stripe, create_customer_on_sign_up: false)
    cookie = sign_up_cookie(auth, email: "fallback-upgrade@example.com")

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "pro", successUrl: "/success", cancelUrl: "/cancel"}
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    assert_equal "cus_upgrade_existing", auth.context.internal_adapter.find_user_by_id(user.fetch("id")).fetch("stripeCustomerId")
    assert_empty stripe.customers.created
    assert_equal({email: "fallback-upgrade@example.com", limit: 100}, stripe.customers.list_calls.fetch(0))
  end

  def test_upgrade_rejects_invalid_customer_type
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "invalid-customer-type@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(
        headers: {"cookie" => cookie},
        body: {plan: "pro", customerType: "workspace", successUrl: "/success", cancelUrl: "/cancel"}
      )
    end

    assert_equal "Customer type must be either user or organization", error.message
    assert_empty stripe.customers.created
  end

  def test_checkout_session_params_merge_options_metadata_and_lookup_keys
    stripe = FakeStripeClient.new
    auth = build_auth(
      stripe_client: stripe,
      subscription: {
        enabled: true,
        plans: [{name: "lookup", lookup_key: "lookup_monthly"}],
        get_checkout_session_params: lambda do |_data, _request, _ctx|
          {
            params: {
              allow_promotion_codes: true,
              metadata: {customField: "customValue", referenceId: "attacker"},
              subscription_data: {metadata: {subscriptionField: "subscriptionValue"}}
            },
            options: {idempotency_key: "checkout-lookup"}
          }
        end
      }
    )
    cookie = sign_up_cookie(auth, email: "lookup@example.com")

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "lookup", successUrl: "/success", cancelUrl: "/cancel"}
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    params = stripe.checkout.created.fetch(0)
    assert_equal "price_lookup_123", params.fetch(:line_items).fetch(0).fetch(:price)
    assert_equal true, params.fetch(:allow_promotion_codes)
    assert_equal "customValue", params.fetch(:metadata).fetch("customField")
    refute_equal "attacker", params.fetch(:metadata).fetch("referenceId")
    assert_equal "subscriptionValue", params.fetch(:subscription_data).fetch(:metadata).fetch("subscriptionField")
    assert_equal "checkout-lookup", stripe.checkout.created_options.fetch(0).fetch(:idempotency_key)
  end

  def test_upgrade_rejects_plan_when_price_id_cannot_be_resolved
    stripe = FakeStripeClient.new
    stripe.prices.list_result = {"data" => []}
    auth = build_auth(
      stripe_client: stripe,
      subscription: {
        enabled: true,
        plans: [{name: "missing-price", lookup_key: "missing_lookup"}]
      }
    )
    cookie = sign_up_cookie(auth, email: "missing-price@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(
        headers: {"cookie" => cookie},
        body: {plan: "missing-price", successUrl: "/success", cancelUrl: "/cancel"}
      )
    end

    assert_equal "Price ID not found for the selected plan", error.message
    assert_empty stripe.checkout.created
  end

  def test_lists_cancels_restores_and_opens_billing_portal
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth)
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_test",
        stripeSubscriptionId: "sub_test",
        status: "active",
        periodStart: Time.now,
        periodEnd: Time.now + 3600
      }
    )

    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_test")
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_test", customer: "cus_test", price_id: "price_pro")]

    listed = auth.api.list_active_subscriptions(headers: {"cookie" => cookie})
    assert_equal [subscription.fetch("id")], listed.map { |item| item.fetch("id") }

    canceled = auth.api.cancel_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_test", returnUrl: "http://localhost:3000/settings"})
    assert_equal "https://stripe.test/portal", canceled.fetch(:url)
    auth.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {cancelAtPeriodEnd: true})

    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_test", customer: "cus_test", price_id: "price_pro", cancel_at_period_end: true)]
    restored = auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_test"})
    assert_equal "sub_test", restored.fetch(:id)
    assert_equal false, auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}]).fetch("cancelAtPeriodEnd")

    portal = auth.api.create_billing_portal(headers: {"cookie" => cookie}, body: {returnUrl: "http://localhost:3000/settings"})
    assert_equal "https://stripe.test/portal", portal.fetch(:url)
  end

  def test_list_active_subscriptions_returns_annual_price_for_yearly_subscription
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "annual-list@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_annual",
        stripeSubscriptionId: "sub_annual",
        status: "active",
        billingInterval: "year"
      }
    )

    listed = auth.api.list_active_subscriptions(headers: {"cookie" => cookie})

    assert_equal [subscription.fetch("id")], listed.map { |item| item.fetch("id") }
    assert_equal "price_pro_year", listed.fetch(0).fetch("priceId")
  end

  def test_metered_checkout_line_item_omits_quantity
    stripe = FakeStripeClient.new
    stripe.prices.retrieve_data["price_metered"] = {"id" => "price_metered", "recurring" => {"usage_type" => "metered"}}
    auth = build_auth(
      stripe_client: stripe,
      subscription: {
        enabled: true,
        plans: [{name: "metered", price_id: "price_metered"}]
      }
    )
    cookie = sign_up_cookie(auth, email: "metered@example.com")

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "metered", successUrl: "/success", cancelUrl: "/cancel"}
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    line_item = stripe.checkout.created.fetch(0).fetch(:line_items).fetch(0)
    assert_equal "price_metered", line_item.fetch(:price)
    refute line_item.key?(:quantity)
  end

  def test_metered_billing_portal_update_item_omits_quantity
    stripe = FakeStripeClient.new
    stripe.prices.retrieve_data["price_metered"] = {"id" => "price_metered", "recurring" => {"usage_type" => "metered"}}
    auth = build_auth(
      stripe_client: stripe,
      subscription: {
        enabled: true,
        plans: [
          {name: "basic", price_id: "price_basic"},
          {name: "metered", price_id: "price_metered"}
        ]
      }
    )
    cookie = sign_up_cookie(auth, email: "metered-portal@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_metered_portal")
    auth.context.adapter.create(
      model: "subscription",
      data: {plan: "basic", referenceId: user.fetch("id"), stripeCustomerId: "cus_metered_portal", stripeSubscriptionId: "sub_metered_portal", status: "active", seats: 1, periodEnd: Time.now + 86_400}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_metered_portal", customer: "cus_metered_portal", price_id: "price_basic")]

    portal = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "metered", seats: 5, successUrl: "/success", cancelUrl: "/cancel", returnUrl: "/billing"}
    )

    assert_equal "https://stripe.test/portal", portal.fetch(:url)
    item = stripe.billing_portal.created.fetch(0).dig(:flow_data, :subscription_update_confirm, :items).fetch(0)
    assert_equal "price_metered", item.fetch(:price)
    assert_equal "si_sub_metered_portal", item.fetch(:id)
    refute item.key?(:quantity)
  end

  def test_schedules_plan_change_at_period_end_and_restore_releases_schedule
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "schedule@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_schedule")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "basic", referenceId: user.fetch("id"), stripeCustomerId: "cus_schedule", stripeSubscriptionId: "sub_schedule", status: "active", seats: 1, periodEnd: Time.now + 86_400}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_schedule", customer: "cus_schedule", price_id: "price_basic", status: "active")]

    result = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "pro", scheduleAtPeriodEnd: true, successUrl: "/success", cancelUrl: "/cancel", returnUrl: "/billing"}
    )

    assert_equal "http://localhost:3000/api/auth/billing", result.fetch(:url)
    assert_equal({from_subscription: "sub_schedule"}, stripe.subscription_schedules.created.fetch(0))
    schedule_update = stripe.subscription_schedules.updated.fetch(0)
    assert_equal "sched_1", schedule_update.fetch(:id)
    assert_equal "release", schedule_update.fetch(:params).fetch(:end_behavior)
    assert_equal "price_pro", schedule_update.fetch(:params).fetch(:phases).fetch(1).fetch(:items).fetch(0).fetch(:price)
    scheduled = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "sched_1", scheduled.fetch("stripeScheduleId")

    restored = auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_schedule"})

    assert_equal "sched_1", restored.fetch("id")
    assert_equal ["sched_1"], stripe.subscription_schedules.released
    cleared = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_nil cleared["stripeScheduleId"]
  end

  def test_webhook_verifies_signature_and_updates_subscription
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: "user-1", stripeSubscriptionId: "sub_test", status: "incomplete"}
    )

    event = {
      type: "customer.subscription.updated",
      data: {
        object: {
          id: "sub_test",
          status: "active",
          current_period_start: 1_700_000_000,
          current_period_end: 1_700_086_400,
          cancel_at_period_end: false,
          items: {data: [{quantity: 1, current_period_start: 1_700_000_000, current_period_end: 1_700_086_400, price: {id: "price_pro"}}]}
        }
      }
    }

    result = auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: event)

    assert_equal({success: true}, result)
    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "active", updated.fetch("status")
  end

  def test_webhook_creates_subscription_from_created_event_metadata
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    event = {
      type: "customer.subscription.created",
      data: {
        object: {
          id: "sub_created",
          customer: "cus_created",
          status: "active",
          current_period_start: 1_700_000_000,
          current_period_end: 1_700_086_400,
          cancel_at_period_end: false,
          items: {data: [{quantity: 1, current_period_start: 1_700_000_000, current_period_end: 1_700_086_400, price: {id: "price_pro"}}]},
          metadata: {plan: "pro", referenceId: "user-created", customerType: "user"}
        }
      }
    }

    result = auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: event)

    assert_equal({success: true}, result)
    created = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_created"}])
    assert_equal "pro", created.fetch("plan")
    assert_equal "user-created", created.fetch("referenceId")
    assert_equal "cus_created", created.fetch("stripeCustomerId")
    assert_equal "active", created.fetch("status")
  end

  def test_upgrade_protects_internal_metadata_applies_seats_and_prevents_trial_abuse
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "trial@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    existing = auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "basic",
        referenceId: user.fetch("id"),
        stripeCustomerId: "cus_trial",
        stripeSubscriptionId: "sub_trial_old",
        status: "canceled",
        trialStart: Time.now - 86_400,
        trialEnd: Time.now - 3_600,
        seats: 1
      }
    )
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_trial")

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {
        plan: "pro",
        seats: 3,
        metadata: {userId: "attacker", subscriptionId: existing.fetch("id"), referenceId: "other", note: "kept"},
        successUrl: "/success",
        cancelUrl: "/cancel"
      }
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    params = stripe.checkout.created.last
    assert_equal "price_pro", params.fetch(:line_items).first.fetch(:price)
    assert_equal 3, params.fetch(:line_items).first.fetch(:quantity)
    refute params.fetch(:subscription_data).key?(:trial_period_days)
    metadata = params.fetch(:subscription_data).fetch(:metadata)
    refute_equal "attacker", metadata.fetch("userId")
    refute_equal existing.fetch("id"), metadata.fetch("subscriptionId")
    refute_equal "other", metadata.fetch("referenceId")
    assert_equal "kept", metadata.fetch("note")

    new_subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "status", value: "incomplete"}])
    assert_equal 3, new_subscription.fetch("seats")

    auth.context.adapter.update(
      model: "subscription",
      where: [{field: "id", value: new_subscription.fetch("id")}],
      update: {status: "active", stripeSubscriptionId: "sub_active", periodEnd: Time.now + 86_400}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_active", customer: "cus_trial", price_id: "price_pro", quantity: 3)]
    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", seats: 3, successUrl: "/success", cancelUrl: "/cancel"})
    end
    assert_equal "You're already subscribed to this plan", error.message

    portal = auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", seats: 5, successUrl: "/success", cancelUrl: "/cancel", returnUrl: "/billing"})
    assert_equal "https://stripe.test/portal", portal.fetch(:url)
    assert_equal 5, stripe.billing_portal.created.last.dig(:flow_data, :subscription_update_confirm, :items).first.fetch(:quantity)
  end

  def test_reference_authorization_blocks_cross_reference_operations
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "owner@example.com")
    other_subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: "other-user", stripeCustomerId: "cus_other", stripeSubscriptionId: "sub_other", status: "active"}
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.cancel_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_other", returnUrl: "/billing"})
    end
    assert_equal "Subscription not found", error.message

    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "pro", referenceId: "other-user", successUrl: "/success", cancelUrl: "/cancel"})
    end
    assert_equal "Reference id is not allowed", error.message
    assert_equal "active", auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: other_subscription.fetch("id")}]).fetch("status")
  end

  def test_webhook_event_matrix_and_callbacks
    events = []
    stripe = FakeStripeClient.new
    stripe.subscriptions.retrieve_data["sub_checkout"] = stripe_subscription(
      id: "sub_checkout",
      price_id: "price_pro",
      status: "trialing",
      quantity: 4,
      trial_start: 1_700_000_000,
      trial_end: 1_700_086_400
    )
    auth = build_auth(
      stripe_client: stripe,
      stripe_webhook_secret: "whsec_test",
      on_event: ->(event) { events << [:event, event[:type] || event["type"]] },
      subscription: subscription_options.merge(
        plans: [
          {name: "basic", price_id: "price_basic"},
          {name: "pro", price_id: "price_pro", annual_discount_price_id: "price_pro_year", limits: {projects: 10}, free_trial: {days: 14, on_trial_start: ->(subscription) { events << [:trial_start, subscription.fetch("id")] }}}
        ],
        on_subscription_complete: ->(data, _ctx) { events << [:complete, data.fetch(:subscription).fetch("status")] },
        on_subscription_created: ->(data) { events << [:created, data.fetch(:subscription).fetch("referenceId")] },
        on_subscription_update: ->(data) { events << [:update, data.fetch(:subscription).fetch("status")] },
        on_subscription_cancel: ->(data) { events << [:cancel, data.fetch(:subscription).fetch("id")] },
        on_subscription_deleted: ->(data) { events << [:deleted, data.fetch(:subscription).fetch("id")] }
      )
    )
    user = create_user(auth, email: "webhook@example.com", stripeCustomerId: "cus_webhook")
    incomplete = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_webhook", status: "incomplete"}
    )

    checkout_event = {
      type: "checkout.session.completed",
      data: {object: {mode: "subscription", subscription: "sub_checkout", customer: "cus_webhook", client_reference_id: user.fetch("id"), metadata: {subscriptionId: incomplete.fetch("id"), referenceId: user.fetch("id")}}}
    }
    assert_equal({success: true}, auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: checkout_event))
    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: incomplete.fetch("id")}])
    assert_equal "trialing", updated.fetch("status")
    assert_equal 4, updated.fetch("seats")
    assert_equal "sub_checkout", updated.fetch("stripeSubscriptionId")

    created_event = {
      type: "customer.subscription.created",
      data: {object: stripe_subscription(id: "sub_dashboard", customer: "cus_webhook", price_id: "price_pro", status: "active", quantity: 2)}
    }
    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: created_event)
    created = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_dashboard"}])
    assert_equal user.fetch("id"), created.fetch("referenceId")
    assert_equal 2, created.fetch("seats")

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: created_event)
    assert_equal 1, auth.context.adapter.find_many(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_dashboard"}]).length

    update_event = {
      type: "customer.subscription.updated",
      data: {object: stripe_subscription(id: "sub_dashboard", customer: "cus_webhook", price_id: "price_basic", status: "active", quantity: 7, cancel_at_period_end: true, canceled_at: 1_700_000_100)}
    }
    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: update_event)
    changed = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: created.fetch("id")}])
    assert_equal "basic", changed.fetch("plan")
    assert_equal 7, changed.fetch("seats")
    assert_equal true, changed.fetch("cancelAtPeriodEnd")

    deleted_event = {
      type: "customer.subscription.deleted",
      data: {object: stripe_subscription(id: "sub_dashboard", customer: "cus_webhook", price_id: "price_basic", status: "canceled", ended_at: 1_700_000_200)}
    }
    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: deleted_event)
    deleted = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: created.fetch("id")}])
    assert_equal "canceled", deleted.fetch("status")
    assert deleted.fetch("endedAt")

    assert_includes events, [:complete, "trialing"]
    assert_includes events, [:trial_start, incomplete.fetch("id")]
    assert_includes events, [:created, user.fetch("id")]
    assert_includes events, [:update, "active"]
    assert_includes events, [:cancel, created.fetch("id")]
    assert_includes events, [:deleted, created.fetch("id")]
    assert_equal 5, events.count { |event| event.first == :event }
  end

  def test_subscription_success_cancel_callback_restore_and_webhook_errors
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    cookie = sign_up_cookie(auth, email: "states@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_states")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_states", stripeSubscriptionId: "sub_states", status: "incomplete"}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_states", customer: "cus_states", price_id: "price_pro", status: "active", quantity: 2)]

    status, headers, = auth.api.subscription_success(headers: {"cookie" => cookie}, query: {callbackURL: "/done", subscriptionId: subscription.fetch("id")}, as_response: true)
    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth/done", headers.fetch("location")
    synced = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "active", synced.fetch("status")
    assert_equal 2, synced.fetch("seats")

    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_states", customer: "cus_states", price_id: "price_pro", status: "active", cancel_at_period_end: true, canceled_at: 1_700_000_111)]
    status, headers, = auth.api.cancel_subscription_callback(headers: {"cookie" => cookie}, query: {callbackURL: "/billing", subscriptionId: subscription.fetch("id")}, as_response: true)
    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth/billing", headers.fetch("location")
    pending = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal true, pending.fetch("cancelAtPeriodEnd")
    assert pending.fetch("canceledAt")

    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_states", customer: "cus_states", price_id: "price_pro", status: "active", cancel_at: 1_700_010_000)]
    stripe.subscriptions.update_result = stripe_subscription(id: "sub_states", customer: "cus_states", price_id: "price_pro", status: "active")
    restored = auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_states"})
    assert_equal "sub_states", restored.fetch("id")
    restored_record = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal false, restored_record.fetch("cancelAtPeriodEnd")
    assert_nil restored_record.fetch("cancelAt")
    assert_nil restored_record.fetch("canceledAt")
    assert_equal({cancel_at: ""}, stripe.subscriptions.updated.last.fetch(:params))

    assert_raises(BetterAuth::APIError) { auth.api.stripe_webhook(headers: {}, body: {type: "invoice.paid"}) }

    stripe.webhooks.async = true
    assert_equal({success: true}, auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "invoice.paid"}))
    assert_equal ["payload", "valid", "whsec_test"], stripe.webhooks.constructed_async_args
  end

  def test_webhook_prefers_construct_event_async_when_available
    stripe = FakeStripeClient.new
    stripe.webhooks.async_event = {type: "invoice.paid"}
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")

    result = auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "invoice.paid"})

    assert_equal({success: true}, result)
    assert_equal ["payload", "valid", "whsec_test"], stripe.webhooks.constructed_async_args
    assert_nil stripe.webhooks.constructed_sync_args
  end

  def test_webhook_processing_errors_return_webhook_error
    stripe = FakeStripeClient.new
    auth = build_auth(
      stripe_client: stripe,
      stripe_webhook_secret: "whsec_test",
      on_event: ->(_event) { raise "processing failed" }
    )

    error = assert_raises(BetterAuth::APIError) do
      auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: {type: "invoice.paid"})
    end

    assert_equal "Stripe webhook error", error.message
  end

  def test_subscription_success_uses_checkout_session_metadata_and_replaces_placeholder
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe)
    cookie = sign_up_cookie(auth, email: "checkout-success@example.com")
    user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
    auth.context.internal_adapter.update_user(user.fetch("id"), stripeCustomerId: "cus_success")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: user.fetch("id"), stripeCustomerId: "cus_success", status: "incomplete"}
    )
    stripe.checkout.retrieve_data["cs_success"] = {"id" => "cs_success", "metadata" => {"subscriptionId" => subscription.fetch("id")}}
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_success", customer: "cus_success", price_id: "price_pro", status: "active", quantity: 2)]

    status, headers, = auth.api.subscription_success(
      headers: {"cookie" => cookie},
      query: {callbackURL: "/done/{CHECKOUT_SESSION_ID}", checkoutSessionId: "cs_success"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/api/auth/done/cs_success", headers.fetch("location")
    synced = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "active", synced.fetch("status")
    assert_equal "sub_success", synced.fetch("stripeSubscriptionId")
  end

  def test_subscription_webhook_syncs_interval_schedule_and_clears_stale_cancel_fields
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {
        plan: "pro",
        referenceId: "user-interval",
        stripeCustomerId: "cus_interval",
        stripeSubscriptionId: "sub_interval",
        status: "active",
        cancelAt: Time.at(1_700_010_000),
        canceledAt: Time.at(1_700_000_000),
        endedAt: Time.at(1_700_020_000),
        stripeScheduleId: "sub_sched_old"
      }
    )

    event = {
      type: "customer.subscription.updated",
      data: {
        object: stripe_subscription(
          id: "sub_interval",
          customer: "cus_interval",
          price_id: "price_pro_year",
          status: "active",
          cancel_at_period_end: false,
          cancel_at: nil,
          canceled_at: nil,
          ended_at: nil,
          schedule: "sub_sched_new",
          interval: "year"
        )
      }
    }

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: event)

    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "year", updated.fetch("billingInterval")
    assert_equal "sub_sched_new", updated.fetch("stripeScheduleId")
    assert_nil updated["cancelAt"]
    assert_nil updated["canceledAt"]
    assert_nil updated["endedAt"]
  end

  def test_subscription_update_resolves_plan_item_from_multi_item_subscription
    stripe = FakeStripeClient.new
    auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "basic", referenceId: "user-multi-item", stripeCustomerId: "cus_multi", stripeSubscriptionId: "sub_multi", status: "active", seats: 1}
    )
    event = {
      type: "customer.subscription.updated",
      data: {
        object: stripe_subscription(
          id: "sub_multi",
          customer: "cus_multi",
          price_id: "price_addon",
          status: "active",
          quantity: 99,
          extra_items: [
            {
              id: "si_plan_sub_multi",
              quantity: 3,
              current_period_start: 1_700_000_000,
              current_period_end: 1_700_086_400,
              price: {id: "price_pro", lookup_key: nil, recurring: {interval: "month"}}
            }
          ]
        )
      }
    }

    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: event)

    updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "pro", updated.fetch("plan")
    assert_equal 3, updated.fetch("seats")
  end

  def test_subscription_update_invokes_trial_end_and_expired_callbacks
    stripe = FakeStripeClient.new
    callbacks = []
    auth = build_auth(
      stripe_client: stripe,
      stripe_webhook_secret: "whsec_test",
      subscription: subscription_options.merge(
        plans: [
          {
            name: "pro",
            price_id: "price_pro",
            free_trial: {
              days: 14,
              on_trial_end: ->(payload, _ctx = nil) { callbacks << [:end, payload.fetch(:subscription).fetch("id")] },
              on_trial_expired: ->(subscription, _ctx = nil) { callbacks << [:expired, subscription.fetch("id")] }
            }
          }
        ]
      )
    )
    ended_subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: "user-trial-end", stripeCustomerId: "cus_trial_end", stripeSubscriptionId: "sub_trial_end", status: "trialing"}
    )
    expired_subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "pro", referenceId: "user-trial-expired", stripeCustomerId: "cus_trial_expired", stripeSubscriptionId: "sub_trial_expired", status: "trialing"}
    )

    auth.api.stripe_webhook(
      headers: {"stripe-signature" => "valid"},
      body: {type: "customer.subscription.updated", data: {object: stripe_subscription(id: "sub_trial_end", customer: "cus_trial_end", price_id: "price_pro", status: "active")}}
    )
    auth.api.stripe_webhook(
      headers: {"stripe-signature" => "valid"},
      body: {type: "customer.subscription.updated", data: {object: stripe_subscription(id: "sub_trial_expired", customer: "cus_trial_expired", price_id: "price_pro", status: "incomplete_expired")}}
    )

    assert_includes callbacks, [:end, ended_subscription.fetch("id")]
    assert_includes callbacks, [:expired, expired_subscription.fetch("id")]
  end

  def test_builds_official_stripe_client_adapter_from_api_key
    plugin = BetterAuth::Plugins.stripe(stripe_api_key: "sk_test_123")

    client = BetterAuth::Plugins.stripe_client(plugin.options)

    assert_instance_of BetterAuth::Stripe::ClientAdapter, client
    assert client.respond_to?(:customers)
    assert_same client, BetterAuth::Plugins.stripe_client(plugin.options)
  end

  def test_builds_official_stripe_client_adapter_from_env_secret
    previous_secret = ENV["STRIPE_SECRET_KEY"]
    ENV["STRIPE_SECRET_KEY"] = "sk_test_env"
    plugin = BetterAuth::Plugins.stripe

    client = BetterAuth::Plugins.stripe_client(plugin.options)

    assert_instance_of BetterAuth::Stripe::ClientAdapter, client
  ensure
    previous_secret ? ENV["STRIPE_SECRET_KEY"] = previous_secret : ENV.delete("STRIPE_SECRET_KEY")
  end

  def test_missing_client_and_api_key_raise_helpful_error
    previous_secret = ENV.delete("STRIPE_SECRET_KEY")
    plugin = BetterAuth::Plugins.stripe

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.stripe_client(plugin.options)
    end

    assert_includes error.message, "Stripe client is required"
  ensure
    ENV["STRIPE_SECRET_KEY"] = previous_secret if previous_secret
  end

  private

  def build_auth(options = {})
    plugin_options = {
      subscription: subscription_options
    }.merge(options)
    plugin_options[:subscription] = subscription_options.merge(plugin_options[:subscription] || {}) if plugin_options[:subscription].is_a?(Hash)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.stripe(plugin_options)
      ]
    )
  end

  def subscription_options
    {
      enabled: true,
      plans: [
        {name: "basic", price_id: "price_basic"},
        {name: "pro", price_id: "price_pro", annual_discount_price_id: "price_pro_year", limits: {projects: 10}, free_trial: {days: 14}}
      ]
    }
  end

  def sign_up_cookie(auth, email: "billing@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Billing User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def create_user(auth, data = {})
    auth.context.internal_adapter.create_user({email: "user-#{SecureRandom.hex(4)}@example.com", name: "User", emailVerified: true}.merge(data.transform_keys(&:to_s)))
  end

  def stripe_subscription(id:, customer: "cus_test", price_id: "price_pro", lookup_key: nil, status: "active", quantity: 1, current_period_start: 1_700_000_000, current_period_end: 1_700_086_400, cancel_at_period_end: false, cancel_at: nil, canceled_at: nil, ended_at: nil, trial_start: nil, trial_end: nil, metadata: {}, schedule: nil, interval: nil, extra_items: [])
    {
      id: id,
      customer: customer,
      status: status,
      schedule: schedule,
      cancel_at_period_end: cancel_at_period_end,
      cancel_at: cancel_at,
      canceled_at: canceled_at,
      ended_at: ended_at,
      trial_start: trial_start,
      trial_end: trial_end,
      metadata: metadata,
      items: {
        data: [
          {
            id: "si_#{id}",
            quantity: quantity,
            current_period_start: current_period_start,
            current_period_end: current_period_end,
            price: {id: price_id, lookup_key: lookup_key, recurring: {interval: interval}}
          }
        ] + extra_items
      }
    }
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  class FakeStripeClient
    attr_reader :customers, :checkout, :billing_portal, :subscriptions, :webhooks, :prices, :subscription_schedules

    def initialize
      @customers = Customers.new
      @checkout = Checkout.new
      @billing_portal = BillingPortal.new
      @subscriptions = Subscriptions.new
      @webhooks = Webhooks.new
      @prices = Prices.new
      @subscription_schedules = SubscriptionSchedules.new
    end

    class Customers
      attr_accessor :search_error, :search_data, :list_data, :create_error
      attr_reader :created, :list_calls, :search_calls

      def initialize
        @created = []
        @list_calls = []
        @search_calls = []
        @list_data = []
      end

      def create(params)
        raise create_error if create_error

        metadata = params[:metadata] || params["metadata"] || {}
        customer = {
          "id" => "cus_#{created.length + 1}",
          "email" => params[:email],
          "name" => params[:name],
          "metadata" => metadata,
          :metadata => metadata
        }.merge(params.except(:email, :name, :metadata))
        created << customer
        customer
      end

      def search(query:, **params)
        search_calls << {query: query}.merge(params)
        raise search_error if search_error

        {"data" => search_data || []}
      end

      def list(**params)
        list_calls << params
        data = list_data.select do |customer|
          params[:email].nil? || (customer[:email] || customer["email"]) == params[:email]
        end
        {"data" => data}
      end

      def retrieve(_id)
        {"id" => "cus_test", "deleted" => false, "name" => "Billing User"}
      end

      def update(id, params)
        {"id" => id}.merge(params.transform_keys(&:to_s))
      end
    end

    class Checkout
      attr_accessor :retrieve_data
      attr_reader :created, :created_options

      def initialize
        @created = []
        @created_options = []
        @retrieve_data = {}
      end

      def sessions
        self
      end

      def create(params, options = nil)
        created << params
        created_options << (options || {})
        {"id" => "cs_test", "url" => "https://stripe.test/checkout", "subscription" => "checkout-subscription", "customer" => "cus_checkout"}
      end

      def retrieve(id)
        retrieve_data[id]
      end
    end

    class Prices
      attr_accessor :list_result
      attr_reader :list_calls
      attr_reader :retrieve_data

      def initialize
        @list_calls = []
        @retrieve_data = {}
      end

      def list(params)
        list_calls << params
        list_result || {"data" => [{"id" => "price_lookup_123"}]}
      end

      def retrieve(id)
        retrieve_data[id] || {"id" => id, "recurring" => {"usage_type" => "licensed"}}
      end
    end

    class BillingPortal
      attr_reader :created

      def initialize
        @created = []
      end

      def sessions
        self
      end

      def create(params)
        created << params
        {"url" => "https://stripe.test/portal"}
      end
    end

    class SubscriptionSchedules
      attr_reader :created, :updated, :released, :retrieve_data

      def initialize
        @created = []
        @updated = []
        @released = []
        @retrieve_data = {}
      end

      def create(params)
        created << params
        {
          "id" => "sched_1",
          "status" => "active",
          "phases" => [
            {
              "start_date" => 1_700_000_000,
              "end_date" => 1_700_086_400,
              "items" => [{"price" => "price_basic", "quantity" => 1}]
            }
          ]
        }
      end

      def update(id, params)
        updated << {id: id, params: params}
        {"id" => id}.merge(params.transform_keys(&:to_s))
      end

      def retrieve(id)
        retrieve_data[id] || {"id" => id, "status" => "active"}
      end

      def release(id)
        released << id
        {"id" => id, "status" => "released"}
      end

      def list(**_params)
        {"data" => []}
      end
    end

    class Subscriptions
      attr_accessor :list_data, :update_result
      attr_reader :updated, :retrieve_data

      def initialize
        @list_data = []
        @retrieve_data = {}
        @updated = []
      end

      def update(id, params = {})
        updated << {id: id, params: params}
        update_result || {"id" => id, "status" => params[:cancel_at_period_end] ? "canceled" : "active"}
      end

      def retrieve(id)
        retrieve_data[id] || {"id" => id, "status" => "active"}
      end

      def list(**params)
        data = list_data.select do |subscription|
          params[:customer].nil? || (subscription[:customer] || subscription["customer"]) == params[:customer]
        end
        {"data" => data}
      end
    end

    class Webhooks
      attr_accessor :async, :async_event
      attr_reader :constructed_async_args, :constructed_sync_args

      def construct_event(payload, signature, secret)
        @constructed_sync_args = ["payload", signature, secret]
        raise "invalid signature" unless signature == "valid" && secret == "whsec_test"

        payload
      end

      def construct_event_async(payload, signature, secret)
        @constructed_async_args = ["payload", signature, secret]
        raise "invalid signature" unless signature == "valid" && secret == "whsec_test"

        async_event || payload
      end
    end
  end
end
