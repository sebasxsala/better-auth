# Stripe High-Value Parity Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 21 high-value Ruby tests for `better_auth-stripe` that cover the highest-risk upstream Stripe behaviors before releasing the modularized package.

**Architecture:** Keep the implementation unchanged unless a new test exposes a real parity bug. Add targeted Minitest coverage to the new modular test files where possible, and keep behavior-heavy end-to-end coverage in the existing fake Stripe integration suites. Prioritize public behavior, database state, webhook processing, customer/reference authorization, schema merging, and seat-based billing over duplicating every upstream test 1:1.

**Tech Stack:** Ruby 3.2+, Minitest, StandardRB, `better_auth-stripe`, fake Stripe client fixtures already defined in `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb` and `stripe_organization_test.rb`, upstream Better Auth `v1.6.9` tests under `upstream/packages/stripe/test`.

---

## Required Context

- [x] Read root `AGENTS.md`.
- [x] Checked `packages/better_auth-stripe` for package-level `AGENTS.md`; none exists.
- [x] Reviewed current Ruby Stripe tests:
  - `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`
  - `packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb`
  - `packages/better_auth-stripe/test/better_auth/stripe/**/*_test.rb`
- [x] Reviewed upstream test inventory:
  - `upstream/packages/stripe/test/stripe.test.ts`
  - `upstream/packages/stripe/test/stripe-organization.test.ts`
  - `upstream/packages/stripe/test/seat-based-billing.test.ts`
  - `upstream/packages/stripe/test/metadata.test.ts`
  - `upstream/packages/stripe/test/utils.test.ts`
- [x] Current Ruby suite after modularization: 99 tests.
- [x] Upstream Stripe suite count: 150 tests.

## Scope

- [ ] Add 21 new tests.
- [x] Do not port all upstream tests 1:1.
- [x] Prefer database-backed Better Auth behavior over isolated mocks.
- [x] Use existing fake Stripe helpers instead of introducing a new fake client.
- [x] Do not bump gem version in this plan.
- [x] Only change implementation if a new test reveals a real bug.
- [x] If a Ruby-specific adaptation is chosen, document it in this plan before committing.

Ruby-specific adaptation discovered in Task 1: `options[:schema]` must preserve custom field names such as `billingEmail` instead of normalizing them to `billing_email`, while still normalizing table/config keys. This matches upstream `mergeSchema` behavior and keeps user-defined schema fields addressable by their declared Better Auth names. Task 1 also exposed that the Ruby plugin omitted upstream's public `version` metadata, so `PluginFactory` now passes `BetterAuth::Stripe::VERSION` into `BetterAuth::Plugin.new`.

Ruby-specific adaptation in Task 3: the Ruby API returns `BetterAuth::Response` for redirect responses, so the checkout-session placeholder test asserts through `response.status` and `response.headers`. The list route preserves the plan `limits` keys as configured; the test declares string keys and asserts string keys.

Ruby-specific adaptation in Task 5: organization records use string keys in the Ruby test helpers, and `FakeStripeClient` is scoped as `BetterAuthPluginsStripeTest::FakeStripeClient`. The seat sync no-op test sets the fake Stripe seat item quantity to the expected member count after adding the member, because the organization hook runs after membership mutation.

## Target Test Additions

### Schema And Factory Coverage: 4 tests

- [x] `BetterAuthStripeSchemaTest#test_custom_user_schema_merges_with_stripe_customer_field`
- [x] `BetterAuthStripeSchemaTest#test_custom_organization_schema_merges_when_organization_enabled`
- [x] `BetterAuthStripeSchemaTest#test_custom_subscription_schema_merges_when_subscription_enabled`
- [x] `BetterAuthStripePluginFactoryTest#test_plugin_version_is_exposed`

### Authorization And Reference Guards: 4 tests

- [x] `BetterAuthStripeMiddlewareTest#test_explicit_other_user_reference_requires_authorize_reference`
- [x] `BetterAuthStripeMiddlewareTest#test_authorize_reference_callback_can_allow_other_user_reference`
- [x] `BetterAuthStripeMiddlewareTest#test_organization_reference_requires_active_organization_or_reference_id`
- [x] `BetterAuthStripeMiddlewareTest#test_organization_reference_requires_authorize_reference_callback`

### Route Behavior Coverage: 5 tests

- [x] `BetterAuthStripeRoutesCancelSubscriptionTest#test_cancel_route_syncs_when_stripe_reports_already_canceled`
- [x] `BetterAuthStripeRoutesRestoreSubscriptionTest#test_restore_route_clears_cancel_at_period_end`
- [x] `BetterAuthStripeRoutesRestoreSubscriptionTest#test_restore_route_releases_pending_schedule`
- [x] `BetterAuthStripeRoutesListActiveSubscriptionsTest#test_list_route_returns_limits_and_annual_price_id`
- [x] `BetterAuthStripeRoutesSubscriptionSuccessTest#test_success_route_replaces_checkout_session_placeholder`

### Webhook Edge Coverage: 4 tests

- [x] `BetterAuthStripeRoutesStripeWebhookTest#test_webhook_rejects_missing_signature`
- [x] `BetterAuthStripeRoutesStripeWebhookTest#test_webhook_rejects_missing_secret`
- [x] `BetterAuthStripeRoutesStripeWebhookTest#test_webhook_rejects_null_constructed_event`
- [x] `BetterAuthStripeHooksTest#test_subscription_created_hook_skips_when_customer_reference_is_missing`

### Seat-Based Billing Coverage: 4 tests

- [x] `BetterAuthStripeOrganizationHooksTest#test_sync_seats_uses_custom_proration_behavior`
- [x] `BetterAuthStripeOrganizationHooksTest#test_sync_seats_does_not_update_when_quantity_matches`
- [x] `BetterAuthStripeRoutesUpgradeSubscriptionTest#test_seat_only_plan_does_not_duplicate_base_price`
- [x] `BetterAuthStripeRoutesUpgradeSubscriptionTest#test_metered_seat_upgrade_keeps_quantity_only_for_seat_item`

## Task 1: Schema And Plugin Factory Tests

**Files:**
- Modify: `packages/better_auth-stripe/test/better_auth/stripe/schema_test.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/stripe/plugin_factory_test.rb`

- [x] **Step 1: Add schema merge tests**

Append these tests to `BetterAuthStripeSchemaTest`:

```ruby
def test_custom_user_schema_merges_with_stripe_customer_field
  schema = BetterAuth::Stripe::Schema.schema(
    schema: {
      user: {
        fields: {
          role: {type: "string", required: false}
        }
      }
    }
  )

  fields = schema.fetch(:user).fetch(:fields)
  assert_equal({type: "string", required: false}, fields.fetch(:stripeCustomerId))
  assert_equal({type: "string", required: false}, fields.fetch(:role))
end

def test_custom_organization_schema_merges_when_organization_enabled
  schema = BetterAuth::Stripe::Schema.schema(
    organization: {enabled: true},
    schema: {
      organization: {
        fields: {
          billingEmail: {type: "string", required: false}
        }
      }
    }
  )

  fields = schema.fetch(:organization).fetch(:fields)
  assert_equal({type: "string", required: false}, fields.fetch(:stripeCustomerId))
  assert_equal({type: "string", required: false}, fields.fetch(:billingEmail))
end

def test_custom_subscription_schema_merges_when_subscription_enabled
  schema = BetterAuth::Stripe::Schema.schema(
    subscription: {enabled: true, plans: []},
    schema: {
      subscription: {
        fields: {
          entitlement: {type: "string", required: false}
        }
      }
    }
  )

  fields = schema.fetch(:subscription).fetch(:fields)
  assert_equal({type: "string", required: true}, fields.fetch(:plan))
  assert_equal({type: "string", required: false}, fields.fetch(:entitlement))
end
```

- [x] **Step 2: Add plugin version test**

Append this test to `BetterAuthStripePluginFactoryTest`:

```ruby
def test_plugin_version_is_exposed
  plugin = BetterAuth::Stripe::PluginFactory.build

  assert_equal BetterAuth::Stripe::VERSION, plugin.version
end
```

- [x] **Step 3: Run focused tests and verify pass**

Run:

```bash
cd packages/better_auth-stripe
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/schema_test.rb
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/plugin_factory_test.rb
```

Expected: both files pass.

- [x] **Step 4: Commit**

```bash
git add packages/better_auth-stripe/test/better_auth/stripe/schema_test.rb packages/better_auth-stripe/test/better_auth/stripe/plugin_factory_test.rb .docs/plans/2026-05-02-0040--stripe-high-value-parity-tests.md
git commit -m "test(stripe): cover schema merge parity"
```

## Task 2: Authorization And Reference Guard Tests

**Files:**
- Modify: `packages/better_auth-stripe/test/better_auth/stripe/middleware_test.rb`

- [x] **Step 1: Add user reference authorization tests**

Append these tests to `BetterAuthStripeMiddlewareTest`:

```ruby
def test_explicit_other_user_reference_requires_authorize_reference
  session = {
    user: {"id" => "user_123"},
    session: {"id" => "session_123"}
  }

  error = assert_raises(BetterAuth::APIError) do
    BetterAuth::Stripe::Middleware.authorize_reference!(
      nil,
      session,
      "user_456",
      "upgrade-subscription",
      "user",
      {},
      explicit: true
    )
  end

  assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("REFERENCE_ID_NOT_ALLOWED"), error.message
end

def test_authorize_reference_callback_can_allow_other_user_reference
  session = {
    user: {"id" => "user_123"},
    session: {"id" => "session_123"}
  }
  calls = []
  options = {
    authorize_reference: lambda do |payload, _ctx|
      calls << payload
      payload[:referenceId] == "user_456" && payload[:action] == "upgrade-subscription"
    end
  }

  assert_nil BetterAuth::Stripe::Middleware.authorize_reference!(
    nil,
    session,
    "user_456",
    "upgrade-subscription",
    "user",
    options,
    explicit: true
  )
  assert_equal 1, calls.length
end
```

- [x] **Step 2: Add organization reference authorization tests**

Append these tests to `BetterAuthStripeMiddlewareTest`:

```ruby
def test_organization_reference_requires_active_organization_or_reference_id
  session = {
    user: {"id" => "user_123"},
    session: {}
  }

  error = assert_raises(BetterAuth::APIError) do
    BetterAuth::Stripe::Middleware.reference_id!(
      nil,
      session,
      "organization",
      nil,
      {organization: {enabled: true}}
    )
  end

  assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("ORGANIZATION_REFERENCE_ID_REQUIRED"), error.message
end

def test_organization_reference_requires_authorize_reference_callback
  session = {
    user: {"id" => "user_123"},
    session: {"activeOrganizationId" => "org_123"}
  }

  error = assert_raises(BetterAuth::APIError) do
    BetterAuth::Stripe::Middleware.authorize_reference!(
      nil,
      session,
      "org_123",
      "upgrade-subscription",
      "organization",
      {},
      explicit: false
    )
  end

  assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("AUTHORIZE_REFERENCE_REQUIRED"), error.message
end
```

- [x] **Step 3: Run focused tests and verify pass**

Run:

```bash
cd packages/better_auth-stripe
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/middleware_test.rb
```

Expected: middleware tests pass.

- [x] **Step 4: Commit**

```bash
git add packages/better_auth-stripe/test/better_auth/stripe/middleware_test.rb .docs/plans/2026-05-02-0040--stripe-high-value-parity-tests.md
git commit -m "test(stripe): cover reference authorization guards"
```

## Task 3: Route Behavior Tests

**Files:**
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`
- Modify: route test files under `packages/better_auth-stripe/test/better_auth/stripe/routes/`

- [x] **Step 1: Add cancel route behavior test wrapper**

Add this behavior test to `BetterAuthPluginsStripeTest` in `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`, because the fake Stripe/auth helpers currently live in that integration file:

```ruby
def test_cancel_route_syncs_when_stripe_reports_already_canceled
  stripe = FakeStripeClient.new
  auth = build_auth(stripe_client: stripe)
  cookie = sign_up_cookie(auth, email: "cancel-sync-route@example.com")
  user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
  subscription = auth.context.adapter.create(
    model: "subscription",
    data: {
      plan: "pro",
      referenceId: user.fetch("id"),
      stripeCustomerId: "cus_cancel_route",
      stripeSubscriptionId: "sub_cancel_route",
      status: "active"
    }
  )
  stripe.subscriptions.list_data = [
    stripe_subscription(id: "sub_cancel_route", customer: "cus_cancel_route", cancel_at_period_end: true)
  ]
  stripe.billing_portal.create_error = RuntimeError.new("already set to be canceled")

  error = assert_raises(BetterAuth::APIError) do
    auth.api.cancel_subscription(
      headers: {"cookie" => cookie},
      body: {subscriptionId: "sub_cancel_route", returnUrl: "/account"}
    )
  end

  assert_includes error.message, "already set to be canceled"
  updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}])
  assert_equal true, updated.fetch("cancelAtPeriodEnd")
end
```

- [x] **Step 2: Add restore route cancel-at-period-end test**

Add this behavior test to `BetterAuthPluginsStripeTest` in `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`:

```ruby
def test_restore_route_clears_cancel_at_period_end
  stripe = FakeStripeClient.new
  auth = build_auth(stripe_client: stripe)
  cookie = sign_up_cookie(auth, email: "restore-period-route@example.com")
  user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
  auth.context.adapter.create(
    model: "subscription",
    data: {
      plan: "pro",
      referenceId: user.fetch("id"),
      stripeCustomerId: "cus_restore_period",
      stripeSubscriptionId: "sub_restore_period",
      status: "active",
      cancelAtPeriodEnd: true
    }
  )
  stripe.subscriptions.list_data = [
    stripe_subscription(id: "sub_restore_period", customer: "cus_restore_period", cancel_at_period_end: true)
  ]

  auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_restore_period"})

  updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_restore_period"}])
  assert_equal false, updated.fetch("cancelAtPeriodEnd")
  assert_equal({cancel_at_period_end: false}, stripe.subscriptions.updated.fetch(0).fetch(:params))
end
```

- [x] **Step 3: Add restore route schedule release test**

Add this behavior test to `BetterAuthPluginsStripeTest` in `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`:

```ruby
def test_restore_route_releases_pending_schedule
  stripe = FakeStripeClient.new
  auth = build_auth(stripe_client: stripe)
  cookie = sign_up_cookie(auth, email: "restore-schedule-route@example.com")
  user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
  auth.context.adapter.create(
    model: "subscription",
    data: {
      plan: "pro",
      referenceId: user.fetch("id"),
      stripeCustomerId: "cus_restore_schedule",
      stripeSubscriptionId: "sub_restore_schedule",
      status: "active",
      stripeScheduleId: "sched_restore_route"
    }
  )
  stripe.subscription_schedules.retrieve_data = {"id" => "sched_restore_route", "status" => "active"}

  auth.api.restore_subscription(headers: {"cookie" => cookie}, body: {subscriptionId: "sub_restore_schedule"})

  updated = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_restore_schedule"}])
  assert_nil updated["stripeScheduleId"]
  assert_equal "sched_restore_route", stripe.subscription_schedules.released.fetch(0)
end
```

- [x] **Step 4: Add list route limits and annual price test**

Add this behavior test to `BetterAuthPluginsStripeTest` in `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`:

```ruby
def test_list_route_returns_limits_and_annual_price_id
  stripe = FakeStripeClient.new
  auth = build_auth(stripe_client: stripe)
  cookie = sign_up_cookie(auth, email: "list-limits-route@example.com")
  user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
  auth.context.adapter.create(
    model: "subscription",
    data: {
      plan: "pro",
      referenceId: user.fetch("id"),
      stripeCustomerId: "cus_list_limits",
      stripeSubscriptionId: "sub_list_limits",
      status: "active",
      billingInterval: "year"
    }
  )

  subscriptions = auth.api.list_active_subscriptions(headers: {"cookie" => cookie})

  assert_equal "price_pro_year", subscriptions.fetch(0).fetch("priceId")
  assert_equal({"projects" => 10}, subscriptions.fetch(0).fetch("limits"))
end
```

Use `build_auth(subscription: {enabled: true, plans: [{name: "pro", price_id: "price_pro_month", annual_discount_price_id: "price_pro_year", limits: {"projects" => 10}}]})` in this test setup so the expected annual price and limits are explicit in the test.

- [x] **Step 5: Add success route checkout-session callback replacement test**

Add this behavior test to `BetterAuthPluginsStripeTest` in `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`:

```ruby
def test_success_route_replaces_checkout_session_placeholder
  stripe = FakeStripeClient.new
  auth = build_auth(stripe_client: stripe)
  cookie = sign_up_cookie(auth, email: "success-placeholder-route@example.com")
  user = auth.api.get_session(headers: {"cookie" => cookie})[:user]
  subscription = auth.context.adapter.create(
    model: "subscription",
    data: {
      plan: "pro",
      referenceId: user.fetch("id"),
      stripeCustomerId: "cus_success_placeholder",
      status: "incomplete"
    }
  )
  stripe.checkout.retrieve_data["cs_success_placeholder"] = {
    "id" => "cs_success_placeholder",
    "metadata" => {"subscriptionId" => subscription.fetch("id")}
  }
  stripe.subscriptions.list_data = [
    stripe_subscription(id: "sub_success_placeholder", customer: "cus_success_placeholder")
  ]

  response = auth.api.subscription_success(
    headers: {"cookie" => cookie},
    query: {
      callbackURL: "/done?session={CHECKOUT_SESSION_ID}",
      checkoutSessionId: "cs_success_placeholder"
    },
    as_response: true
  )

  assert_equal 302, response.fetch(0)
  assert_includes response.fetch(1).fetch("location"), "session=cs_success_placeholder"
end
```

- [x] **Step 6: Run focused route/integration tests**

Run:

```bash
cd packages/better_auth-stripe
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/plugins/stripe_test.rb
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/cancel_subscription_test.rb
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/restore_subscription_test.rb
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/list_active_subscriptions_test.rb
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/subscription_success_test.rb
```

Expected: all focused route/integration tests pass.

- [x] **Step 7: Commit**

```bash
git add packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb packages/better_auth-stripe/test/better_auth/stripe/routes .docs/plans/2026-05-02-0040--stripe-high-value-parity-tests.md
git commit -m "test(stripe): cover subscription route behavior"
```

## Task 4: Webhook Edge Tests

**Files:**
- Modify: `packages/better_auth-stripe/test/better_auth/stripe/routes/stripe_webhook_test.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/stripe/hooks_test.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`

- [x] **Step 1: Add webhook route missing signature test**

Add this behavior test to `BetterAuthPluginsStripeTest` in `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`:

```ruby
def test_webhook_rejects_missing_signature
  stripe = FakeStripeClient.new
  auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")

  error = assert_raises(BetterAuth::APIError) do
    auth.api.stripe_webhook(headers: {}, body: {type: "customer.subscription.updated"})
  end

  assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("STRIPE_SIGNATURE_NOT_FOUND"), error.message
end
```

- [x] **Step 2: Add webhook route missing secret test**

Add this behavior test to `BetterAuthPluginsStripeTest` in `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`:

```ruby
def test_webhook_rejects_missing_secret
  stripe = FakeStripeClient.new
  auth = build_auth(stripe_client: stripe, stripe_webhook_secret: nil)

  error = assert_raises(BetterAuth::APIError) do
    auth.api.stripe_webhook(headers: {"stripe-signature" => "sig_test"}, body: {type: "customer.subscription.updated"})
  end

  assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("STRIPE_WEBHOOK_SECRET_NOT_FOUND"), error.message
end
```

- [x] **Step 3: Add webhook null constructed event test**

Add this behavior test to `BetterAuthPluginsStripeTest` in `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`:

```ruby
def test_webhook_rejects_null_constructed_event
  stripe = FakeStripeClient.new
  stripe.webhooks.constructed_event = nil
  auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")

  error = assert_raises(BetterAuth::APIError) do
    auth.api.stripe_webhook(headers: {"stripe-signature" => "sig_test"}, body: {type: "customer.subscription.updated"})
  end

  assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT"), error.message
end
```

- [x] **Step 4: Add hook missing customer reference test**

Add this behavior test to `BetterAuthPluginsStripeTest` in `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb` using the public webhook endpoint:

```ruby
def test_subscription_created_hook_skips_when_customer_reference_is_missing
  stripe = FakeStripeClient.new
  stripe.webhooks.constructed_event = {
    type: "customer.subscription.created",
    data: {
      object: stripe_subscription(
        id: "sub_missing_reference",
        customer: "cus_missing_reference",
        metadata: {}
      )
    }
  }
  auth = build_auth(stripe_client: stripe, stripe_webhook_secret: "whsec_test")

  auth.api.stripe_webhook(headers: {"stripe-signature" => "sig_test"}, body: "{}")

  subscription = auth.context.adapter.find_one(model: "subscription", where: [{field: "stripeSubscriptionId", value: "sub_missing_reference"}])
  assert_nil subscription
end
```

- [x] **Step 5: Run focused webhook tests**

Run:

```bash
cd packages/better_auth-stripe
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/plugins/stripe_test.rb
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/stripe_webhook_test.rb
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/hooks_test.rb
```

Expected: all focused webhook tests pass.

- [x] **Step 6: Commit**

```bash
git add packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb packages/better_auth-stripe/test/better_auth/stripe/routes/stripe_webhook_test.rb packages/better_auth-stripe/test/better_auth/stripe/hooks_test.rb .docs/plans/2026-05-02-0040--stripe-high-value-parity-tests.md
git commit -m "test(stripe): cover webhook edge cases"
```

## Task 5: Seat-Based Billing Tests

**Files:**
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/stripe/organization_hooks_test.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/stripe/routes/upgrade_subscription_test.rb`

- [x] **Step 1: Add sync seats proration behavior test**

Add this behavior test to `BetterAuthPluginsStripeOrganizationTest` in `packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb` using the existing `build_seat_auth` helper:

```ruby
def test_sync_seats_uses_custom_proration_behavior
  stripe = FakeStripeClient.new
  auth = build_seat_auth(stripe, proration_behavior: "always_invoice")
  cookie = sign_up_cookie(auth, "seat-proration@example.com")
  organization = auth.api.create_organization(
    headers: {"cookie" => cookie},
    body: {name: "Seat Proration Org", slug: "seat-proration-org"}
  )
  auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch(:id)}], update: {stripeCustomerId: "cus_seat_proration"})
  auth.context.adapter.create(
    model: "subscription",
    data: {
      plan: "team",
      referenceId: organization.fetch(:id),
      stripeCustomerId: "cus_seat_proration",
      stripeSubscriptionId: "sub_seat_proration",
      status: "active"
    }
  )
  stripe.subscriptions.retrieve_data = stripe_subscription(id: "sub_seat_proration", customer: "cus_seat_proration", quantity: 1)
  member_user = auth.context.internal_adapter.create_user(email: "seat-proration-member@example.com", name: "Member", emailVerified: true)

  auth.api.add_member(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch(:id), userId: member_user.fetch("id"), role: "member"})

  assert_equal "always_invoice", stripe.subscriptions.updated.fetch(0).fetch(:params).fetch(:proration_behavior)
end
```

- [x] **Step 2: Add sync seats no-op test when quantity matches**

Add this test:

```ruby
def test_sync_seats_does_not_update_when_quantity_matches
  stripe = FakeStripeClient.new
  auth = build_seat_auth(stripe)
  cookie = sign_up_cookie(auth, "seat-noop@example.com")
  organization = auth.api.create_organization(
    headers: {"cookie" => cookie},
    body: {name: "Seat Noop Org", slug: "seat-noop-org"}
  )
  auth.context.adapter.update(model: "organization", where: [{field: "id", value: organization.fetch(:id)}], update: {stripeCustomerId: "cus_seat_noop"})
  auth.context.adapter.create(
    model: "subscription",
    data: {
      plan: "team",
      referenceId: organization.fetch(:id),
      stripeCustomerId: "cus_seat_noop",
      stripeSubscriptionId: "sub_seat_noop",
      status: "active"
    }
  )
  member_count = auth.context.adapter.count(model: "member", where: [{field: "organizationId", value: organization.fetch(:id)}])
  stripe.subscriptions.retrieve_data = stripe_subscription(id: "sub_seat_noop", customer: "cus_seat_noop", quantity: member_count)
  member_user = auth.context.internal_adapter.create_user(email: "seat-noop-member@example.com", name: "Member", emailVerified: true)

  auth.api.add_member(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch(:id), userId: member_user.fetch("id"), role: "member"})

  assert_empty stripe.subscriptions.updated
end
```

- [x] **Step 3: Add seat-only plan checkout duplication test**

Add this behavior test to `BetterAuthPluginsStripeOrganizationTest` in `packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb` using `build_seat_auth`:

```ruby
def test_seat_only_plan_does_not_duplicate_base_price
  stripe = FakeStripeClient.new
  auth = build_seat_auth(stripe)
  cookie = sign_up_cookie(auth, "seat-only@example.com")
  organization = auth.api.create_organization(
    headers: {"cookie" => cookie},
    body: {name: "Seat Only Org", slug: "seat-only-org"}
  )

  auth.api.upgrade_subscription(
    headers: {"cookie" => cookie},
    body: {
      plan: "team",
      customerType: "organization",
      referenceId: organization.fetch(:id),
      successUrl: "/success",
      cancelUrl: "/cancel"
    }
  )

  line_items = stripe.checkout.created.fetch(0).fetch(:line_items)
  prices = line_items.map { |item| item.fetch(:price) }
  assert_equal prices.uniq, prices
end
```

- [x] **Step 4: Add metered seat upgrade quantity test**

Add this behavior test to `BetterAuthPluginsStripeOrganizationTest` in `packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb`:

```ruby
def test_metered_seat_upgrade_keeps_quantity_only_for_seat_item
  stripe = FakeStripeClient.new
  stripe.prices.retrieve_data = {"id" => "price_metered", "recurring" => {"usage_type" => "metered"}}
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
          plans: [{name: "team", price_id: "price_metered", seat_price_id: "price_team_seat"}],
          authorize_reference: ->(_data, _ctx) { true }
        }
      )
    ]
  )
  cookie = sign_up_cookie(auth, "metered-seat@example.com")
  organization = auth.api.create_organization(
    headers: {"cookie" => cookie},
    body: {name: "Metered Seat Org", slug: "metered-seat-org"}
  )

  auth.api.upgrade_subscription(
    headers: {"cookie" => cookie},
    body: {
      plan: "team",
      customerType: "organization",
      referenceId: organization.fetch(:id),
      successUrl: "/success",
      cancelUrl: "/cancel"
    }
  )

  line_items = stripe.checkout.created.fetch(0).fetch(:line_items)
  base_item = line_items.find { |item| item.fetch(:price) == "price_metered" }
  seat_item = line_items.find { |item| item.fetch(:price) == "price_team_seat" }
  refute base_item.key?(:quantity)
  assert_operator seat_item.fetch(:quantity), :>=, 1
end
```

- [x] **Step 5: Run focused organization tests**

Run:

```bash
cd packages/better_auth-stripe
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/plugins/stripe_organization_test.rb
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/organization_hooks_test.rb
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/upgrade_subscription_test.rb
```

Expected: all focused seat/organization tests pass.

- [x] **Step 6: Commit**

```bash
git add packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb packages/better_auth-stripe/test/better_auth/stripe/organization_hooks_test.rb packages/better_auth-stripe/test/better_auth/stripe/routes/upgrade_subscription_test.rb .docs/plans/2026-05-02-0040--stripe-high-value-parity-tests.md
git commit -m "test(stripe): cover seat billing edge cases"
```

## Task 6: Final Verification

**Files:**
- Modify: `.docs/plans/2026-05-02-0040--stripe-high-value-parity-tests.md`

- [ ] **Step 1: Run full package suite**

Run:

```bash
cd packages/better_auth-stripe
rbenv exec bundle exec rake test
```

Expected: all tests pass. The suite should have 120 tests after this plan.

- [ ] **Step 2: Run style check**

Run:

```bash
cd packages/better_auth-stripe
rbenv exec bundle exec standardrb
```

Expected: exits with status 0.

- [ ] **Step 3: Run root smoke**

Run:

```bash
rbenv exec bundle exec ruby -Ipackages/better_auth-stripe/lib -e 'require "better_auth/stripe"; plugin = BetterAuth::Plugins.stripe(subscription: {enabled: true, plans: []}); puts plugin.id'
```

Expected: prints `stripe`.

- [ ] **Step 4: Update this plan with final counts**

Append the exact final verification output below this step after running the commands. The expected final test count is 120 because this plan adds 21 tests to the current 99-test suite.

- [ ] **Step 5: Commit**

```bash
git add .docs/plans/2026-05-02-0040--stripe-high-value-parity-tests.md
git commit -m "docs(stripe): complete high-value parity test plan"
```

## Self-Review

- [x] Spec coverage: plan targets the requested 15-25 high-value tests and includes 21 concrete tests.
- [x] Placeholder scan: no generic "write tests" steps; every planned test has a name, target file, and expected assertions.
- [x] Type consistency: all test names use current Ruby module/class names and existing Better Auth Stripe naming.
- [x] Risk focus: tests prioritize schema/options, reference authorization, route behavior, webhooks, and seat billing.
