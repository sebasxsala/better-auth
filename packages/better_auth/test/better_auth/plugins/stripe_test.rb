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
    assert_equal "checkout-subscription", subscription.fetch("stripeSubscriptionId")
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

    listed = auth.api.list_active_subscriptions(headers: {"cookie" => cookie})
    assert_equal [subscription.fetch("id")], listed.fetch(:subscriptions).map { |item| item.fetch("id") }

    canceled = auth.api.cancel_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: subscription.fetch("id"), returnUrl: "http://localhost:3000/settings"})
    assert_equal true, canceled.fetch(:success)
    assert_equal "canceled", auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}]).fetch("status")

    restored = auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: subscription.fetch("id")})
    assert_equal true, restored.fetch(:success)
    assert_equal "active", auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}]).fetch("status")

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
          cancel_at_period_end: false
        }
      }
    }

    result = auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: event)

    assert_equal({received: true}, result)
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
          metadata: {plan: "pro", referenceId: "user-created", customerType: "user"}
        }
      }
    }

    result = auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: event)

    assert_equal({received: true}, result)
    created = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_created"}])
    assert_equal "pro", created.fetch("plan")
    assert_equal "user-created", created.fetch("referenceId")
    assert_equal "cus_created", created.fetch("stripeCustomerId")
    assert_equal "active", created.fetch("status")
  end

  private

  def build_auth(options = {})
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.stripe({
          subscription: {
            enabled: true,
            plans: [{name: "pro", price_id: "price_pro"}]
          }
        }.merge(options))
      ]
    )
  end

  def sign_up_cookie(auth)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "billing@example.com", password: "password123", name: "Billing User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
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
      def sessions
        self
      end

      def create(_params)
        {"id" => "cs_test", "url" => "https://stripe.test/checkout", "subscription" => "checkout-subscription", "customer" => "cus_checkout"}
      end
    end

    class BillingPortal
      def sessions
        self
      end

      def create(_params)
        {"url" => "https://stripe.test/portal"}
      end
    end

    class Subscriptions
      def update(id, params = {})
        {"id" => id, "status" => params[:cancel_at_period_end] ? "canceled" : "active"}
      end

      def retrieve(id)
        {"id" => id, "status" => "active"}
      end

      def list(**_params)
        {"data" => []}
      end
    end

    class Webhooks
      def construct_event(payload, signature, secret)
        raise "invalid signature" unless signature == "valid" && secret == "whsec_test"

        payload
      end
    end
  end
end
