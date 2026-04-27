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

  def stripe_subscription(id:, customer: "cus_test", price_id: "price_pro", lookup_key: nil, status: "active", quantity: 1, current_period_start: 1_700_000_000, current_period_end: 1_700_086_400, cancel_at_period_end: false, cancel_at: nil, canceled_at: nil, ended_at: nil, trial_start: nil, trial_end: nil, metadata: {})
    {
      id: id,
      customer: customer,
      status: status,
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
            price: {id: price_id, lookup_key: lookup_key}
          }
        ]
      }
    }
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  class FakeStripeClient
    attr_reader :customers, :checkout, :billing_portal, :subscriptions, :webhooks

    def initialize
      @customers = Customers.new
      @checkout = Checkout.new
      @billing_portal = BillingPortal.new
      @subscriptions = Subscriptions.new
      @webhooks = Webhooks.new
    end

    class Customers
      attr_reader :created

      def initialize
        @created = []
      end

      def create(params)
        customer = {"id" => "cus_#{created.length + 1}", "email" => params[:email], "name" => params[:name], "metadata" => params[:metadata] || {}}
        created << customer
        customer
      end

      def search(query:, **_params)
        {"data" => []}
      end

      def retrieve(_id)
        {"id" => "cus_test", "deleted" => false, "name" => "Billing User"}
      end

      def update(id, params)
        {"id" => id}.merge(params.transform_keys(&:to_s))
      end
    end

    class Checkout
      attr_reader :created

      def initialize
        @created = []
      end

      def sessions
        self
      end

      def create(params, _options = nil)
        created << params
        {"id" => "cs_test", "url" => "https://stripe.test/checkout", "subscription" => "checkout-subscription", "customer" => "cus_checkout"}
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
      attr_accessor :async
      attr_reader :constructed_async_args

      def construct_event(payload, signature, secret)
        raise "invalid signature" unless signature == "valid" && secret == "whsec_test"

        payload
      end

      def construct_event_async(payload, signature, secret)
        return nil unless async

        @constructed_async_args = ["payload", signature, secret]
        construct_event(payload, signature, secret)
      end
    end
  end
end
