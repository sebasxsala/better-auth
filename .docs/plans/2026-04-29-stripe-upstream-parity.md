# Stripe Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:test-driven-development` for every behavior change. Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining behavioral deltas between `packages/better_auth-stripe` and `upstream/packages/stripe` so the Ruby plugin matches Better Auth `v1.6.9` Stripe behavior, error codes, security checks, and webhook semantics.

**Architecture:** Keep the public Ruby module `BetterAuth::Plugins.stripe(options)` API stable. Add the missing error codes, security middleware behavior, raw-body webhook support, plan-change diff logic, and follow the upstream cancel flow without losing the existing Ruby `cancel/callback` adaptation. Where Ruby idioms (snake_case keys, single ClientAdapter façade) diverge intentionally, document them and keep tests for both shapes.

**Tech Stack:** Ruby 3.4.9, Minitest, StandardRB, official `stripe` gem, Better Auth core endpoint/middleware/Routes APIs, upstream Better Auth `packages/stripe` (v1.6.9).

---

## Summary Of Identified Deltas

The Ruby implementation already covers most upstream behavior. The remaining gaps to close are:

1. **Error code drift**
  - Missing: `FAILED_TO_FETCH_PLANS`, `SUBSCRIPTION_NOT_PENDING_CHANGE` (upstream deprecates `SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION` in favor of this).
  - Ruby uses `ORGANIZATION_NOT_FOUND` everywhere, but upstream uses `ORGANIZATION_REFERENCE_ID_REQUIRED` from `referenceMiddleware` (when neither `referenceId` nor `activeOrganizationId` is present) and reserves `ORGANIZATION_NOT_FOUND` for `getReferenceId` and absent organization records.
2. **Security middleware (`originCheck`) is missing on Ruby endpoints**
  - Upstream applies `originCheck` to `successUrl`/`cancelUrl` in upgrade, `returnUrl` in cancel, billing portal, and `callbackURL` in subscription success.
  - Ruby endpoints accept any URL value without origin validation.
3. **Webhook raw-body handling**
  - Upstream uses `cloneRequest: true, disableBody: true` and reads `await ctx.request.text()` so the Stripe signature verifies against the **raw** payload.
  - Ruby passes `ctx.body` (the parsed JSON hash) to `webhooks.construct_event_async`, which fails real Stripe signatures even when the test fakes succeed.
4. `**subscriptionToUpdate` linking**
  - Upstream backfills `stripeSubscriptionId` on a pre-existing dbSubscription that has none when an active Stripe subscription is found. Ruby skips this branch.
5. **Plan-change item delta logic**
  - Upstream maintains a `priceMap` (old → new + qty) and a `lineItemDelta` multiset diff to add/remove line items deterministically for both schedule-at-period-end and direct subscription updates.
  - Ruby's `stripe_update_active_subscription_items` and `stripe_schedule_plan_change` use a simpler "removed/added line prices" array diff that does not preserve duplicates, does not consume positive deltas while iterating active items, and does not release a prior plugin-created schedule before scheduling a new one (only releases inside `restore_subscription`).
6. **Restore endpoint**
  - Should raise `SUBSCRIPTION_NOT_PENDING_CHANGE` (new code) when neither pending cancel nor pending schedule is present (currently uses `SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION`).
  - Upstream returns the released schedule's underlying subscription via `client.subscriptions.retrieve(stripeSubscriptionId)` instead of returning the raw schedule object. Ruby returns the schedule.
7. **Stripe customer search query encoding**
  - Upstream escapes the search value via `escapeStripeSearchValue` (only escapes `"` to `\"`). Ruby's `stripe_escape_search` uses `gsub("\"", "\\\"")` which evaluates to escaping `"` as `\"` in the source but Ruby string interpolation produces a literal backslash-quote — verify the exact wire query matches upstream and add tests around values containing `"`.
8. `**subscription/success` divergences**
  - Upstream uses `originCheck` on `callbackURL`.
  - Upstream computes seats with `resolveQuantity(...) || 1`. Ruby uses `stripe_resolve_quantity` which returns 1 by default but does not OR with 1 again — confirm parity for items missing `quantity`.
9. `**disableRedirect` JSON shape**
  - Upstream `cancelSubscription` returns `{ url, redirect: !disableRedirect }`. Ruby returns the entire stringified portal session merged with `redirect`. This diverges from upstream's response shape and may break clients relying on `{ url, redirect }`.
10. **Cancel endpoint and Ruby's `/subscription/cancel/callback`**
  - Upstream cancellations are resolved via webhook events (no callback endpoint). Ruby kept a callback endpoint that updates the database eagerly when the user returns from the Billing Portal. Document this explicitly as an intentional Ruby adaptation that augments (not replaces) the webhook flow, and ensure the response contract still matches upstream `{ url, redirect }`.
11. `**subscription_data.metadata` precedence in checkout**
  - Upstream merges via `subscriptionMetadata.set(internal, body.metadata, params?.params?.subscription_data?.metadata)` so internal fields win last. Ruby explicitly reassigns `checkout_params[:subscription_data][:metadata]` after `stripe_deep_merge`, but the key path is built only from `custom_subscription_data` rather than the deep-merged result. Verify a custom `subscription_data.metadata` is preserved before internal field overrides land.
12. **Documentation**
  - Update `packages/better_auth-stripe/README.md` and `docs/content/docs/plugins/stripe.mdx` to describe the new error codes, the raw-body webhook requirement, the cancel callback adaptation, and the official `stripe` gem auto-bootstrap.

## File Structure

- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb` — add raw-body access, new error codes, origin checks, schedule release-before-create, plan-change item-delta logic, response shape fix.
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb` — add failing tests first for every behavioral change below.
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb` — extend org tests for `ORGANIZATION_REFERENCE_ID_REQUIRED` and member-count seat sync diff.
- Modify (if needed): `packages/better_auth/lib/better_auth/routes.rb` and `packages/better_auth/lib/better_auth/endpoint.rb` — expose raw request body to plugin endpoints and any helper hooks for `disableBody`/`cloneRequest` semantics.
- Modify: `packages/better_auth-stripe/README.md` and `docs/content/docs/plugins/stripe.mdx` — document the changes and intentional Ruby adaptations.

## Task List

### Task 1: Establish Baseline And Lock Failing Parity Tests

**Files:**

- Verify: `upstream/packages/stripe/src/{index,routes,middleware,hooks,utils,error-codes}.ts`
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb`
- **Step 1: Confirm upstream submodule pin and toolchain**

Run:

```bash
git submodule status upstream
cd upstream && git describe --tags --abbrev=0 && cd ..
rbenv exec ruby -v
```

Expected: submodule at the recorded SHA, tag `v1.6.9`, Ruby 3.4.9.

- **Step 2: Run the existing suites to capture the green baseline**

Run:

```bash
cd packages/better_auth-stripe
rbenv exec bundle exec rake test
RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb
```

Expected: all current tests pass and StandardRB is clean. Record run counts in this plan's verification log.

- **Step 3: Add failing tests for new error codes and middleware messages**

In `stripe_test.rb`, add:

```ruby
def test_error_codes_match_upstream_v1_6_9
  codes = BetterAuth::Plugins::STRIPE_ERROR_CODES
  assert_equal "Failed to fetch plans", codes.fetch("FAILED_TO_FETCH_PLANS")
  assert_equal(
    "Subscription has no pending cancellation or scheduled plan change",
    codes.fetch("SUBSCRIPTION_NOT_PENDING_CHANGE")
  )
  assert_equal(
    "Subscription is not scheduled for cancellation",
    codes.fetch("SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION")
  )
end
```

In `stripe_organization_test.rb`, add a test that the organization reference middleware raises `ORGANIZATION_REFERENCE_ID_REQUIRED` when neither `referenceId` nor `activeOrganizationId` is present, and `ORGANIZATION_NOT_FOUND` only when the organization record is missing in the database.

- **Step 4: Run the new tests to verify failures**

Run:

```bash
cd packages/better_auth-stripe
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_test.rb -n test_error_codes_match_upstream_v1_6_9
```

Expected: failure with `key not found: "FAILED_TO_FETCH_PLANS"`.

### Task 2: Restore-Subscription Pending-Change Code Parity

**Files:**

- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`
- **Step 1: Add failing tests for restore-subscription error codes and return shape**

In `stripe_test.rb`, write tests that assert:

1. Restore raises `SUBSCRIPTION_NOT_PENDING_CHANGE` when no pending cancel and no `stripeScheduleId` is set.
2. After releasing a plugin-created schedule, the response body equals the underlying retrieved Stripe subscription (not the schedule object), to match upstream `subscriptions.retrieve(...)` return.

```ruby
def test_restore_returns_underlying_subscription_after_releasing_schedule
  # arrange a subscription with stripeScheduleId, stub schedules.retrieve+release and subscriptions.retrieve
  # ...
  response = restore!(ctx)
  assert_equal "sub_active", response[:id] # underlying subscription, not the schedule
end

def test_restore_raises_subscription_not_pending_change_when_nothing_pending
  err = assert_raises(BetterAuth::APIError) { restore!(ctx) }
  assert_equal "Subscription has no pending cancellation or scheduled plan change", err.message
end
```

- **Step 2: Add `FAILED_TO_FETCH_PLANS` and `SUBSCRIPTION_NOT_PENDING_CHANGE` to the error code map**

In `stripe.rb`, append to `STRIPE_ERROR_CODES`:

```ruby
"FAILED_TO_FETCH_PLANS" => "Failed to fetch plans",
"SUBSCRIPTION_NOT_PENDING_CHANGE" => "Subscription has no pending cancellation or scheduled plan change",
```

Keep `SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION` for backwards compatibility.

- **Step 3: Update `stripe_restore_subscription_endpoint`**

Replace the schedule branch and the "no pending cancel" branch:

```ruby
if subscription["stripeScheduleId"]
  raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")) if subscription["stripeSubscriptionId"].to_s.empty?

  schedule = stripe_client(config).subscription_schedules.retrieve(subscription["stripeScheduleId"])
  if stripe_fetch(schedule, "status") == "active"
    stripe_client(config).subscription_schedules.release(subscription["stripeScheduleId"])
  end
  ctx.context.adapter.update(model: "subscription", where: [{field: "id", value: subscription.fetch("id")}], update: {stripeScheduleId: nil})
  released_sub = stripe_client(config).subscriptions.retrieve(subscription["stripeSubscriptionId"])
  next ctx.json(stripe_stringify_keys(released_sub))
end

unless stripe_pending_cancel?(subscription)
  raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_PENDING_CHANGE"))
end
```

- **Step 4: Run the restore tests**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_test.rb -n /restore/
```

Expected: PASS.

- **Step 5: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb
git commit -m "feat(stripe): add SUBSCRIPTION_NOT_PENDING_CHANGE and align restore response shape"
```

### Task 3: Reference Middleware Error Code Parity

**Files:**

- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb`
- **Step 1: Failing test for `ORGANIZATION_REFERENCE_ID_REQUIRED`**

In `stripe_organization_test.rb`:

```ruby
def test_organization_reference_id_required_when_no_explicit_or_session_value
  # session has no activeOrganizationId, body has no referenceId, customerType=organization
  # authorize_reference is configured but never called
  err = assert_raises(BetterAuth::APIError) { upgrade!(ctx) }
  assert_equal "Reference ID is required. Provide referenceId or set activeOrganizationId in session", err.message
end
```

And keep an existing `ORGANIZATION_NOT_FOUND` test for the case where the organization record is missing.

- **Step 2: Split `stripe_reference_id!` to preserve both error codes**

Update `stripe_reference_id!` to mirror upstream `referenceMiddleware` + `getReferenceId` semantics:

```ruby
def stripe_reference_id!(ctx, session, customer_type, explicit_reference_id, config)
  return explicit_reference_id || session.fetch(:user).fetch("id") unless customer_type == "organization"
  raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("ORGANIZATION_SUBSCRIPTION_NOT_ENABLED")) unless config.dig(:organization, :enabled)

  reference_id = explicit_reference_id || session.fetch(:session)["activeOrganizationId"]
  if reference_id.to_s.empty?
    raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("ORGANIZATION_REFERENCE_ID_REQUIRED"))
  end
  reference_id
end
```

In `stripe_organization_customer`, keep the existing `ORGANIZATION_NOT_FOUND` branch for the missing-record path.

- **Step 3: Run the test**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_organization_test.rb -n test_organization_reference_id_required_when_no_explicit_or_session_value
```

Expected: PASS.

- **Step 4: Commit**

```bash
git commit -am "fix(stripe): emit ORGANIZATION_REFERENCE_ID_REQUIRED for org reference middleware"
```

### Task 4: Origin Checks On Redirect URLs

**Files:**

- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`
- Verify: `packages/better_auth/lib/better_auth/middleware/origin_check.rb` (existing request-header check) and add a new `packages/better_auth/lib/better_auth/security/origin_check.rb` for body/query URL validation.
- **Step 1: Add a body-URL `origin_check!` helper in core**

`Middleware::OriginCheck` already validates the **request `Origin` header** against `trusted_origins`. Upstream's `originCheck((ctx) => ctx.body.successUrl)` validates a **URL value carried in body/query** against the same allow-list. Add a new helper alongside the existing middleware (do not modify `Middleware::OriginCheck`).

```ruby
module BetterAuth
  module Security
    module_function

    def origin_check!(ctx, *urls)
      base = ctx.context.options.base_url.to_s
      trusted = Array(ctx.context.options.trusted_origins).map(&:to_s)
      urls.compact.each do |url|
        next unless url.is_a?(String) && !url.empty?
        next if url.start_with?("/")
        next if same_origin?(url, base) || trusted.any? { |t| same_origin?(url, t) }
        raise APIError.new("FORBIDDEN", message: "Untrusted origin")
      end
    end

    def same_origin?(a, b)
      ua = URI.parse(a) rescue nil
      ub = URI.parse(b) rescue nil
      ua && ub && ua.scheme == ub.scheme && ua.host == ub.host && ua.port == ub.port
    end
  end
end
```

If a helper already exists, reuse it.

- **Step 2: Failing tests proving origin enforcement**

In `stripe_test.rb`:

```ruby
def test_upgrade_rejects_untrusted_success_url
  err = assert_raises(BetterAuth::APIError) { upgrade!(ctx, success_url: "https://evil.example.com/x") }
  assert_equal "FORBIDDEN", err.code
end

def test_cancel_rejects_untrusted_return_url
  err = assert_raises(BetterAuth::APIError) { cancel!(ctx, return_url: "https://evil.example.com/x") }
  assert_equal "FORBIDDEN", err.code
end

def test_billing_portal_rejects_untrusted_return_url
  err = assert_raises(BetterAuth::APIError) { billing_portal!(ctx, return_url: "https://evil.example.com/x") }
  assert_equal "FORBIDDEN", err.code
end

def test_subscription_success_rejects_untrusted_callback_url
  redirect = follow_redirect!(ctx, callback_url: "https://evil.example.com/x")
  assert_match(/^\//, redirect) # falls back to root, never to attacker URL
end
```

- **Step 3: Wire `origin_check!` into the four endpoints**

In `stripe_upgrade_subscription_endpoint`, after parsing `body`, call `BetterAuth::Security.origin_check!(ctx, body[:success_url], body[:cancel_url])`.

In `stripe_cancel_subscription_endpoint`, call `BetterAuth::Security.origin_check!(ctx, body[:return_url])`.

In `stripe_billing_portal_endpoint`, call `BetterAuth::Security.origin_check!(ctx, body[:return_url])`.

In `stripe_success_endpoint`, call `BetterAuth::Security.origin_check!(ctx, query[:callback_url])` and on failure redirect to `/` instead of raising (to match upstream's `originCheck` returning a 4xx on the GET, but Ruby keeps the redirect-on-failure behavior to stay consistent with the existing endpoint contract; if the helper raises `FORBIDDEN`, rescue in the endpoint and redirect to `/`).

- **Step 4: Run the new tests**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_test.rb -n /origin/
```

Expected: PASS.

- **Step 5: Commit**

```bash
git commit -am "feat(stripe): origin check upgrade/cancel/billing-portal/success URLs"
```

### Task 5: Webhook Raw-Body Support

**Files:**

- Modify: `packages/better_auth/lib/better_auth/endpoint.rb` (or routing layer that constructs the `ctx.request` proxy)
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`
- **Step 1: Failing test that exercises raw-body verification**

In `stripe_test.rb`, add a test that:

1. Posts a JSON body to `/stripe/webhook` along with a valid `Stripe-Signature` derived from `Stripe::Webhook.generate_test_header_string` (or `OpenSSL::HMAC` matching Stripe's spec) for the **byte-exact** payload.
2. Asserts that the endpoint constructs the event without raising and dispatches to `customer.subscription.updated` handler.
3. Adds a second case that mutates a non-significant whitespace in the body (e.g. swaps a space) and asserts the signature **fails** with `FAILED_TO_CONSTRUCT_STRIPE_EVENT`.

This test must currently fail because Ruby passes the parsed hash, not the raw payload string.

- **Step 2: Expose raw body in the endpoint context**

Audit `packages/better_auth/lib/better_auth/endpoint.rb` for how `ctx.body` and `ctx.request` are populated. Add a `ctx.raw_body` (or `ctx.request.text`) that returns the unparsed Rack input (rewind and read), and expose a per-endpoint flag so a plugin can declare `disable_body: true` or `clone_request: true` semantics. The flag should:

- Stop the routing layer from JSON-parsing the body before dispatch.
- Cache the raw payload as a UTF-8 String on the ctx for the plugin to consume.

Document the new option on `Endpoint.new(...)` and update affected plugins (only Stripe needs it for now).

- **Step 3: Switch the webhook endpoint to the raw payload**

```ruby
def stripe_webhook_endpoint(config)
  Endpoint.new(path: "/stripe/webhook", method: "POST", clone_request: true, disable_body: true) do |ctx|
    signature = ctx.headers["stripe-signature"]
    raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("STRIPE_SIGNATURE_NOT_FOUND")) if signature.to_s.empty?
    raise APIError.new("INTERNAL_SERVER_ERROR", message: STRIPE_ERROR_CODES.fetch("STRIPE_WEBHOOK_SECRET_NOT_FOUND")) if config[:stripe_webhook_secret].to_s.empty?

    payload = ctx.raw_body.to_s
    raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("INVALID_REQUEST_BODY")) if payload.empty?

    event = stripe_construct_event!(config, payload, signature)
    # ...rest unchanged...
  end
end

def stripe_construct_event!(config, payload, signature)
  webhooks = stripe_client(config).webhooks
  if webhooks.respond_to?(:construct_event_async)
    webhooks.construct_event_async(payload, signature, config[:stripe_webhook_secret])
  else
    webhooks.construct_event(payload, signature, config[:stripe_webhook_secret])
  end
rescue
  raise APIError.new("BAD_REQUEST", message: STRIPE_ERROR_CODES.fetch("FAILED_TO_CONSTRUCT_STRIPE_EVENT"))
end
```

- **Step 4: Run the webhook tests**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_test.rb -n /webhook/
```

Expected: all webhook tests pass; tampered-payload test correctly raises `FAILED_TO_CONSTRUCT_STRIPE_EVENT`.

- **Step 5: Commit**

```bash
git commit -am "feat(stripe): verify webhook signatures against the raw request payload"
```

### Task 6: Plan-Change Item Delta And Schedule Release

**Files:**

- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`
- **Step 1: Failing tests for plan-change diffs**

Port these scenarios from `upstream/packages/stripe/test/stripe.test.ts` and `seat-based-billing.test.ts`:

1. `should release existing schedule before scheduling a new one` (release pre-existing plugin-created schedule before calling `subscription_schedules.create`).
2. `should not duplicate subscription item when upgrading between seat-only plans` (priceMap should replace, not append, when `plan.seatPriceId === plan.priceId`).
3. `should swap seat item when upgrading to a plan with different seat pricing` (item delta replaces seat item id with new price).
4. `should remove items the new plan no longer needs` (negative deltas issue `{deleted: true}`).
5. `should add items the new plan introduces` (positive deltas append `{price: ...}` items).
6. Mixed: a plan changes seatPriceId AND adds a new line item AND removes an old line item — assert the final `subscriptions.update` items array matches the expected multiset.

- **Step 2: Implement priceMap + lineItemDelta in `stripe_update_active_subscription_items`**

Refactor to mirror upstream:

```ruby
def stripe_update_active_subscription_items(ctx, config, active_stripe, db_subscription, old_plan, plan, price_id, quantity, seat_only_plan, body)
  active_item = stripe_resolve_plan_item(config, active_stripe)&.fetch(:item, nil) || stripe_subscription_item(active_stripe)
  active_price_id = stripe_fetch(stripe_fetch(active_item || {}, "price") || {}, "id")
  is_metered = stripe_metered_price?(config, price_id)
  auto_managed = !!plan[:seat_price_id]
  member_count = quantity # already resolved upstream

  price_map = {}
  if auto_managed && plan[:seat_price_id] && old_plan&.dig(:seat_price_id) && old_plan[:seat_price_id] != plan[:seat_price_id]
    price_map[old_plan[:seat_price_id]] = {new_price: plan[:seat_price_id], quantity: member_count}
  end

  line_item_delta = Hash.new(0)
  Array(old_plan && old_plan[:line_items]).each { |li| line_item_delta[li[:price]] -= 1 if li[:price].is_a?(String) }
  Array(plan[:line_items]).each { |li| line_item_delta[li[:price]] += 1 if li[:price].is_a?(String) }
  line_item_delta.delete_if { |_k, v| v.zero? }

  remove_quota = line_item_delta.each_with_object({}) { |(p, d), acc| acc[p] = -d if d.negative? }

  items = []
  Array(stripe_fetch(stripe_fetch(active_stripe, "items") || {}, "data")).each do |item|
    item_price = stripe_fetch(stripe_fetch(item, "price") || {}, "id")
    if (q = remove_quota[item_price]).to_i.positive?
      remove_quota[item_price] = q - 1
      items << {id: stripe_fetch(item, "id"), deleted: true}
      next
    end
    if (replacement = price_map[item_price])
      items << {id: stripe_fetch(item, "id"), price: replacement[:new_price], quantity: replacement[:quantity] || stripe_fetch(item, "quantity")}
      next
    end
    if item_price == active_price_id
      base = {id: stripe_fetch(item, "id"), price: price_id}
      base[:quantity] = (auto_managed ? 1 : quantity) unless is_metered
      items << base
      next
    end
    if (d = line_item_delta[item_price]) && d.positive?
      d == 1 ? line_item_delta.delete(item_price) : line_item_delta[item_price] = d - 1
    end
  end
  line_item_delta.each { |price, d| d.times { items << {price: price} } if d.positive? }

  stripe_client(config).subscriptions.update(
    stripe_fetch(active_stripe, "id"),
    items: items,
    proration_behavior: plan[:proration_behavior] || "create_prorations"
  )
  if db_subscription
    ctx.context.adapter.update(
      model: "subscription",
      where: [{field: "id", value: db_subscription.fetch("id")}],
      update: {plan: plan[:name].to_s.downcase, seats: quantity, limits: plan[:limits], stripeScheduleId: nil}
    )
  end
  stripe_url(ctx, body[:return_url] || "/")
end
```

Apply the same priceMap + delta logic in `stripe_schedule_plan_change`, and **before creating the schedule** call `subscription_schedules.list({customer: customer_id})` to find an existing schedule whose `metadata.source == "@better-auth/stripe"` and release it (mirroring upstream lines 683-715).

- **Step 3: Run the plan-change tests**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_test.rb -n /upgrade|schedule|seat/i
```

Expected: PASS.

- **Step 4: Commit**

```bash
git commit -am "fix(stripe): mirror upstream priceMap and lineItemDelta in upgrades"
```

### Task 7: Subscription Linking And Response Shape

**Files:**

- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`
- **Step 1: Failing test for stripeSubscriptionId backfill**

Test that when a dbSubscription exists for a referenceId without a `stripeSubscriptionId`, but Stripe has a matching active subscription on the customer, the upgrade flow updates the dbSubscription to point to the live Stripe subscription before continuing.

- **Step 2: Failing test for cancel response shape**

Test that `POST /subscription/cancel` returns exactly `{ url: <portal-url>, redirect: true }` (no other Stripe portal session keys), matching `ctx.json({ url, redirect: !disableRedirect })` upstream.

- **Step 3: Implement backfill in `stripe_upgrade_subscription_endpoint`**

After resolving `active_stripe`, before computing `is_already_subscribed`:

```ruby
if active_stripe && active_or_trialing && active_or_trialing["stripeSubscriptionId"].to_s.empty?
  ctx.context.adapter.update(
    model: "subscription",
    where: [{field: "id", value: active_or_trialing.fetch("id")}],
    update: {stripeSubscriptionId: stripe_fetch(active_stripe, "id")}
  )
  active_or_trialing["stripeSubscriptionId"] = stripe_fetch(active_stripe, "id")
end
```

- **Step 4: Trim the cancel response**

In `stripe_cancel_subscription_endpoint`, replace the merged stringified portal hash with:

```ruby
ctx.json({url: stripe_fetch(portal, "url"), redirect: stripe_redirect?(body)})
```

Audit `stripe_billing_portal_endpoint` and `stripe_upgrade_subscription_endpoint` (when going through Billing Portal flow) to keep the same `{url, redirect}` shape upstream returns.

- **Step 5: Run the targeted tests**

```bash
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_test.rb -n /cancel|backfill|response_shape/i
```

Expected: PASS.

- **Step 6: Commit**

```bash
git commit -am "fix(stripe): align upgrade/cancel response shapes with upstream"
```

### Task 8: Documentation And Final Verification

**Files:**

- Modify: `packages/better_auth-stripe/README.md`
- Modify: `docs/content/docs/plugins/stripe.mdx`
- Modify: `.docs/plans/2026-04-29-stripe-upstream-parity.md`
- **Step 1: Update docs**

Document the following in both README and mdx:

- New error codes `FAILED_TO_FETCH_PLANS`, `SUBSCRIPTION_NOT_PENDING_CHANGE`, kept-deprecated `SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION`.
- Origin check enforcement on `success_url`, `cancel_url`, `return_url`, `callback_url`, including how to register `trusted_origins` in `BetterAuth.configure`.
- The webhook now requires the **raw** request body. Apps must mount `/stripe/webhook` so it receives the unparsed payload (no `JSON.parse` middleware in front of it).
- Intentional Ruby adaptations: `cancel/callback` endpoint augments (not replaces) the webhook flow; the `stripe-ruby` gem `ClientAdapter` is built automatically when only `stripe_api_key` (or `STRIPE_SECRET_KEY`) is provided.
- **Step 2: Run the full suite**

```bash
cd packages/better_auth-stripe
rbenv exec bundle exec rake test
RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb
```

Expected: tests + lint pass.

- **Step 3: Run the core package webhook regression checks**

```bash
cd ../better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/endpoint_test.rb
```

Expected: PASS, ensuring the new `disable_body`/`clone_request` paths do not regress existing endpoints.

- **Step 4: Record run counts in the verification log of this plan**

Open this plan file and append:

```markdown
## Verification Log
- `packages/better_auth-stripe`: rake test → <runs>/<assertions>/<failures>/<errors>/<skips>
- `packages/better_auth-stripe`: standardrb → clean
- `packages/better_auth`: endpoint_test → <runs>/<assertions>/...
```

- **Step 5: Commit**

```bash
git commit -am "docs(stripe): document upstream parity changes and Ruby adaptations"
```

## Assumptions

- The `cancel/callback` endpoint is a Ruby-specific safety net for missed webhooks and will remain. Tests must keep both upstream-shape `{url, redirect}` cancel response and the callback flow working.
- Ruby keeps `snake_case` public options. Endpoints continue to accept Better Auth's `normalize_hash` mixed-case input.
- No version bump or release tag is part of this plan; if a release is requested separately, follow the workspace's `AGENTS.md` versioning rules.
- The cancel-endpoint origin check applies to `body[:return_url]`, not `body[:returnUrl]`. The `normalize_hash` layer covers both wires.

## Open Questions

- Should the Ruby plugin also expose a `cancel_subscription_callback` toggle in options for apps that prefer the pure upstream `{url, redirect}` flow without the eager DB sync?
- Does Better Auth core already have a `trusted_origins` configuration surface, or is this a new option to introduce when implementing `BetterAuth::Security.origin_check!`?

