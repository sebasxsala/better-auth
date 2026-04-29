# frozen_string_literal: true

require_relative "stripe_test"

class BetterAuthPluginsStripeOrganizationTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_organization_customer_schema_rejects_missing_organization
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
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
      email_and_password: {enabled: true},
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

  def test_organization_checkout_uses_seat_price_line_items_and_member_count
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = build_seat_auth(stripe)
    cookie = sign_up_cookie(auth, "seat-checkout@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Seat Checkout", slug: "seat-checkout"})

    checkout = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "team", customerType: "organization", referenceId: organization.fetch("id"), seats: 10, successUrl: "/success", cancelUrl: "/cancel"}
    )

    assert_equal "https://stripe.test/checkout", checkout.fetch(:url)
    params = stripe.checkout.created.fetch(0)
    assert_equal [
      {price: "price_team", quantity: 1},
      {price: "price_team_seat", quantity: 1},
      {price: "price_metered_events"}
    ], params.fetch(:line_items)
    subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "referenceId", value: organization.fetch("id")}])
    assert_equal 1, subscription.fetch("seats")
  end

  def test_organization_member_removal_syncs_seat_quantity
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = build_seat_auth(stripe, proration_behavior: "none")
    owner_cookie = sign_up_cookie(auth, "seat-remove-owner@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Seat Remove", slug: "seat-remove"})
    member_user = auth.context.internal_adapter.create_user(email: "seat-remove-member@example.com", name: "Member", emailVerified: true)
    member = auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), userId: member_user.fetch("id"), role: "member"})
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_seat_remove"})
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "team", referenceId: organization.fetch("id"), stripeCustomerId: "cus_seat_remove", stripeSubscriptionId: "sub_seat_remove", status: "active", seats: 2}
    )
    stripe.subscriptions.retrieve_data["sub_seat_remove"] = stripe_subscription(
      id: "sub_seat_remove",
      customer: "cus_seat_remove",
      price_id: "price_team",
      extra_items: [{id: "si_seat", quantity: 2, price: {id: "price_team_seat"}}]
    )

    auth.api.remove_member(headers: {"cookie" => owner_cookie}, body: {memberId: member.fetch("id")})

    update = stripe.subscriptions.updated.fetch(0)
    assert_equal "sub_seat_remove", update.fetch(:id)
    assert_equal [{id: "si_seat", quantity: 1}], update.fetch(:params).fetch(:items)
    assert_equal "none", update.fetch(:params).fetch(:proration_behavior)
    updated_subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal 1, updated_subscription.fetch("seats")
  end

  def test_accepting_invitation_syncs_seat_quantity
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = build_seat_auth(stripe)
    owner_cookie = sign_up_cookie(auth, "seat-invite-owner@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Seat Invite", slug: "seat-invite"})
    invited_cookie = sign_up_cookie(auth, "seat-invite-member@example.com")
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_seat_invite"})
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "team", referenceId: organization.fetch("id"), stripeCustomerId: "cus_seat_invite", stripeSubscriptionId: "sub_seat_invite", status: "active", seats: 1}
    )
    stripe.subscriptions.retrieve_data["sub_seat_invite"] = stripe_subscription(
      id: "sub_seat_invite",
      customer: "cus_seat_invite",
      price_id: "price_team",
      extra_items: [{id: "si_invite_seat", quantity: 1, price: {id: "price_team_seat"}}]
    )
    invitation = auth.context.adapter.create(
      model: "invitation",
      data: {organizationId: organization.fetch("id"), email: "seat-invite-member@example.com", role: "member", status: "pending", expiresAt: Time.now + 3600, inviterId: auth.api.get_session(headers: {"cookie" => owner_cookie})[:user].fetch("id")}
    )

    auth.api.accept_invitation(headers: {"cookie" => invited_cookie}, body: {invitationId: invitation.fetch("id")})

    update = stripe.subscriptions.updated.fetch(0)
    assert_equal [{id: "si_invite_seat", quantity: 2}], update.fetch(:params).fetch(:items)
    updated_subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal 2, updated_subscription.fetch("seats")
  end

  def test_active_organization_upgrade_with_multiple_item_changes_uses_direct_subscription_update
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    auth = build_multi_item_auth(stripe)
    cookie = sign_up_cookie(auth, "multi-upgrade@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Multi Upgrade", slug: "multi-upgrade"})
    member_user = auth.context.internal_adapter.create_user(email: "multi-member@example.com", name: "Member", emailVerified: true)
    auth.api.add_member(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id"), userId: member_user.fetch("id"), role: "member"})
    auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch("id")}], update: {stripeCustomerId: "cus_multi_upgrade"})
    subscription = auth.context.adapter.create(
      model: "subscription",
      data: {plan: "team", referenceId: organization.fetch("id"), stripeCustomerId: "cus_multi_upgrade", stripeSubscriptionId: "sub_multi_upgrade", status: "active", seats: 2, periodEnd: Time.now + 86_400}
    )
    stripe.subscriptions.list_data = [
      stripe_subscription(
        id: "sub_multi_upgrade",
        customer: "cus_multi_upgrade",
        price_id: "price_team",
        extra_items: [
          {id: "si_old_seat", quantity: 2, price: {id: "price_team_seat"}},
          {id: "si_old_meter", price: {id: "price_old_meter"}}
        ]
      )
    ]

    result = auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "enterprise", customerType: "organization", referenceId: organization.fetch("id"), returnUrl: "/billing", successUrl: "/success", cancelUrl: "/cancel"}
    )

    assert_equal "http://localhost:3000/api/auth/billing", result.fetch(:url)
    assert_empty stripe.billing_portal.created
    update = stripe.subscriptions.updated.fetch(0)
    assert_equal "sub_multi_upgrade", update.fetch(:id)
    assert_equal "always_invoice", update.fetch(:params).fetch(:proration_behavior)
    items = update.fetch(:params).fetch(:items)
    assert_includes items, {id: "si_sub_multi_upgrade", price: "price_enterprise", quantity: 1}
    assert_includes items, {id: "si_old_seat", price: "price_enterprise_seat", quantity: 2}
    assert_includes items, {price: "price_new_meter"}
    updated_subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
    assert_equal "enterprise", updated_subscription.fetch("plan")
    assert_equal 2, updated_subscription.fetch("seats")
  end

  def test_organization_customer_create_params_preserve_metadata_and_callback_shape
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    payloads = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
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

  def test_organization_customer_lookup_requires_organization_customer_type
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    org_customer_id = "cus_org_filtered"
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [{name: "team", price_id: "price_team"}],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, "org-customer-filter@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Filter Org", slug: "filter-org"})
    stripe.customers.search_data = [
      {"id" => "cus_wrong_user", "metadata" => {"organizationId" => organization.fetch("id"), "customerType" => "user"}}
    ]

    stripe.customers.define_singleton_method(:search) do |query:, **params|
      search_calls << {query: query}.merge(params)
      if query.include?(%(metadata["organizationId"]:"#{organization.fetch("id")})) && !query.include?(%(metadata["customerType"]:"organization"))
        {"data" => search_data}
      else
        {"data" => []}
      end
    end
    stripe.customers.define_singleton_method(:create) do |params|
      metadata = params[:metadata] || params["metadata"] || {}
      customer = {"id" => org_customer_id, "metadata" => metadata}.merge(params)
      created << customer
      customer
    end

    auth.api.upgrade_subscription(
      headers: {"cookie" => cookie},
      body: {plan: "team", customerType: "organization", referenceId: organization.fetch("id"), successUrl: "/success", cancelUrl: "/cancel"}
    )

    updated_org = auth.context.adapter.find_one(model: "organization", where: [{field: "id", value: organization.fetch("id")}])
    assert_equal org_customer_id, updated_org.fetch("stripeCustomerId")
    assert_equal %(metadata["organizationId"]:"#{organization.fetch("id")}" AND metadata["customerType"]:"organization"), stripe.customers.search_calls.fetch(0).fetch(:query)
  end

  def test_organization_webhooks_and_delete_guard
    stripe = BetterAuthPluginsStripeTest::FakeStripeClient.new
    deleted_callbacks = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
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

  def build_seat_auth(stripe, proration_behavior: nil)
    plan = {
      name: "team",
      price_id: "price_team",
      seat_price_id: "price_team_seat",
      line_items: [{price: "price_metered_events"}]
    }
    plan[:proration_behavior] = proration_behavior if proration_behavior
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [plan],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
  end

  def build_multi_item_auth(stripe)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.stripe(
          stripe_client: stripe,
          organization: {enabled: true},
          subscription: {
            enabled: true,
            plans: [
              {name: "team", price_id: "price_team", seat_price_id: "price_team_seat", line_items: [{price: "price_old_meter"}]},
              {name: "enterprise", price_id: "price_enterprise", seat_price_id: "price_enterprise_seat", line_items: [{price: "price_new_meter"}], proration_behavior: "always_invoice"}
            ],
            authorize_reference: ->(_data, _ctx) { true }
          }
        )
      ]
    )
  end

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

  def stripe_subscription(id:, customer: "cus_test", price_id: "price_team", lookup_key: nil, status: "active", quantity: 1, current_period_start: 1_700_000_000, current_period_end: 1_700_086_400, cancel_at_period_end: false, cancel_at: nil, canceled_at: nil, ended_at: nil, trial_start: nil, trial_end: nil, metadata: {}, extra_items: [])
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
        ] + extra_items
      }
    }
  end
end
