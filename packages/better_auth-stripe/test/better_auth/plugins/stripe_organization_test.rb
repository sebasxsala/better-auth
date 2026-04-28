# frozen_string_literal: true

require_relative "stripe_test"

class BetterAuthPluginsStripeOrganizationTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_organization_customer_schema_rejects_missing_organization
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.stripe(
          stripe_client: BetterAuthPluginsStripeTest::FakeStripeClient.new,
          organization: {enabled: true},
          subscription: {enabled: true, plans: [{name: "team", price_id: "price_team"}], authorize_reference: ->(_data, _ctx) { true }}
        )
      ]
    )

    assert auth.context.schema.fetch("organization").fetch(:fields).key?("stripeCustomerId")
    cookie = sign_up_cookie(auth, "guard@example.com")
    error = assert_raises(BetterAuth::APIError) do
      auth.api.upgrade_subscription(headers: {"cookie" => cookie}, body: {plan: "team", customerType: "organization", referenceId: "org-1", successUrl: "http://localhost:3000/s", cancelUrl: "http://localhost:3000/c"})
    end
    assert_equal 400, error.status_code
    assert_equal "Organization not found", error.message
  end

  def test_organization_subscription_flow_uses_active_org_and_authorize_reference
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    authorizations = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team"}],
            authorize_reference: ->(data, _ctx) {
              authorizations << [data.fetch(:reference_id), data.fetch(:action)]
              data.fetch(:reference_id) != "blocked-org"
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "org-owner@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Acme", slug: "acme"})
    auth.api.set_active_organization(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id")})
    session_cookie = cookie_header(auth.api.set_active_organization(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id")}, as_response: true)[1].fetch("set-cookie"))

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => session_cookie},
      body: {plan: "team", customerType: "organization", seats: 8, successUrl: "/success", cancelUrl: "/cancel"}
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    updated_org = auth.context.adapter.find_one(model: "organization", where: [{field: "id", value: organization.fetch("id")}])
    assert_match(/\Acus_/, updated_org.fetch("stripeCustomerId"))
    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "referenceId", value: organization.fetch("id")}])
    assert_equal "team", subscription.fetch("plan")
    assert_equal 8, subscription.fetch("seats")
    assert_equal updated_org.fetch("stripeCustomerId"), subscription.fetch("stripeCustomerId")

    auth.context.adapter.update(
      model: "subscription",
      where: [{field: "id", value: subscription.fetch("id")}],
      update: {status: "active", stripeSubscriptionId: "sub_team"}
    )
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_team", customer: updated_org.fetch("stripeCustomerId"), price_id: "price_team")]

    portal = auth.api.create_billing_portal(headers: {"cookie" => session_cookie}, body: {customerType: "organization", returnUrl: "/billing"})
    assert_equal "https://stripe.test/portal", portal.fetch(:url)

    list = auth.api.list_active_subscriptions(headers: {"cookie" => session_cookie}, query: {customerType: "organization"})
    assert_equal [subscription.fetch("id")], list.map { |entry| entry.fetch("id") }

    error = assert_raises(BetterAuth::APIError) do
      auth.api.list_active_subscriptions(headers: {"cookie" => session_cookie}, query: {customerType: "organization", referenceId: "blocked-org"})
    end
    assert_equal "Unauthorized access", error.message
    assert_includes authorizations, [organization.fetch("id"), "upgrade-subscription"]
    assert_includes authorizations, [organization.fetch("id"), "billing-portal"]
    assert_includes authorizations, [organization.fetch("id"), "list-subscription"]
  end

  def test_organization_customer_create_params_preserve_metadata_and_callback_shape
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    payloads = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {
            enabled: true,
            get_customer_create_params: ->(_org, _ctx) { {"email" => "billing@acme.test", "metadata" => {"organizationId" => "attacker", "customOrg" => "kept"}} },
            on_customer_create: ->(payload, _ctx) { payloads << payload }
          },
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team"}],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "org-metadata@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Metadata Org", slug: "metadata-org"})

    auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "team", customerType: "organization", referenceId: organization.fetch("id"), successUrl: "/success", cancelUrl: "/cancel"}
    )

    created = stripe.customers.created.fetch(0)
    assert_equal "billing@acme.test", created.fetch("email")
    assert_equal organization.fetch("id"), created.fetch("metadata").fetch("organizationId")
    assert_equal "organization", created.fetch("metadata").fetch("customerType")
    assert_equal "kept", created.fetch("metadata").fetch("customOrg")
    assert_equal created, payloads.fetch(0).fetch(:stripeCustomer)
    assert_equal created, payloads.fetch(0).fetch(:stripe_customer)
    assert_equal organization.fetch("id"), payloads.fetch(0).fetch(:organization).fetch("id")
    assert_equal created.fetch("id"), payloads.fetch(0).fetch(:organization).fetch("stripeCustomerId")
  end

  def test_organization_webhooks_and_delete_guard
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    deleted_callbacks = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          stripe_webhook_secret: "whsec_test",
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team"}],
            authorize_reference: ->(_data, _ctx) { true },
            on_subscription_deleted: ->(data) { deleted_callbacks << data.fetch(:subscription).fetch("id") }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "org-hooks@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Hooks", slug: "hooks"})
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_org_hooks"})

    created_event = {
      type: "customer.subscription.created",
      data: {object: stripe_subscription(id: "sub_org_created", customer: "cus_org_hooks", price_id: "price_team", status: "active")}
    }
    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: created_event)
    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_org_created"}])
    assert_equal organization.fetch("id"), subscription.fetch("referenceId")

    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_org_created", customer: "cus_org_hooks", price_id: "price_team", status: "active")]
    error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_organization(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id")})
    end
    assert_equal "Cannot delete organization with active subscription", error.message

    deleted_event = {
      type: "customer.subscription.deleted",
      data: {object: stripe_subscription(id: "sub_org_created", customer: "cus_org_hooks", price_id: "price_team", status: "canceled", ended_at: 1_700_000_000)}
    }
    auth.api.stripe_webhook(headers: {"stripe-signature" => "valid"}, body: deleted_event)
    stripe.subscriptions.list_data = [stripe_subscription(id: "sub_org_created", customer: "cus_org_hooks", price_id: "price_team", status: "canceled")]
    assert_equal({status: true}, auth.api.delete_organization(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id")}))
    assert_equal [subscription.fetch("id")], deleted_callbacks
  end

  private

  def sign_up_cookie(auth, email)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Org Owner"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def stripe_subscription(id:, customer: "cus_test", price_id: "price_team", lookup_key: nil, status: "active", quantity: 1, current_period_start: 1_700_000_000, current_period_end: 1_700_086_400, cancel_at_period_end: false, cancel_at: nil, canceled_at: nil, ended_at: nil, trial_start: nil, trial_end: nil, metadata: {})
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
end
