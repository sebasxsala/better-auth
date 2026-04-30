# Stripe Upstream Test Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Translate the missing applicable upstream Stripe package tests into Ruby, then implement the minimum Ruby Stripe plugin fixes until the translated suite passes.

**Architecture:** Treat `upstream/packages/stripe` at Better Auth `v1.6.9` as the source of truth. Keep Ruby tests integration-style through `BetterAuth.auth(... database: :memory ...)`, using the existing `FakeStripeClient` only at the Stripe API boundary.

**Tech Stack:** Ruby, Minitest, BetterAuth plugin system, in-memory adapter, fake Stripe client.

---

### Task 1: Baseline and Test Translation

**Files:**
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb`

- [x] Run the baseline package suite with `cd packages/better_auth-stripe && rbenv exec bundle exec rake test`; expected current result is all green.
- [x] Add utility parity tests for `stripe_escape_search` and `stripe_resolve_plan_item`: double quotes, no quotes, multiple quotes, single item match, empty items, unmatched single item, matching multi-item, unmatched multi-item, and lookup-key match.
- [x] Add user subscription parity tests for cross-user `subscriptionId` rejection, `billingInterval`, created webhook skip branches, schedule id sync/clearing, annual upgrades, custom references, trial prevention, user customer updates, webhook construction errors, reference authorization, line item plan changes, subscription success redirects, and metered pricing.
- [x] Add organization parity tests for existing org customers, cancel/restore/list authorization, cross-org separation, required `authorize_reference`, user/org separation, organization webhook updates/deletes, customer creation errors, callbacks, organization name sync, and deletion without active subscriptions.
- [x] Add seat billing parity tests for member-count seats, no extra line items, seat-only plans, unchanged seat pricing, duplicate prevention, and webhook seat count sync.
- [x] Run the focused Ruby test files and confirm new tests expose real behavior gaps before editing production code.

### Task 2: Fake Stripe Client Support

**Files:**
- Modify: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`

- [x] Extend `FakeStripeClient::Customers` with configurable retrieve/update data and call recording.
- [x] Extend `FakeStripeClient::Checkout` with configurable retrieve errors.
- [x] Extend `FakeStripeClient::Subscriptions` with configurable update errors and list/retrieve behavior needed by cancellation and plan-change tests.
- [x] Extend `FakeStripeClient::SubscriptionSchedules` with configurable list/retrieve/release data.
- [x] Keep fake behavior small and local to the translated tests.

### Task 3: Stripe Plugin Fixes

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`

- [x] Fix only behaviors proven by failing translated tests.
- [x] Preserve Ruby public API naming conventions such as `price_id`, `seat_price_id`, `billingInterval`, and `stripeScheduleId`.
- [x] Keep callbacks compatible with existing symbol and camel-case payload keys.
- [x] Avoid version bumps and unrelated refactors.

### Task 4: Verification

**Files:**
- Verify: `packages/better_auth-stripe`

- [x] Run `cd packages/better_auth-stripe && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_test.rb`.
- [x] Run `cd packages/better_auth-stripe && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_organization_test.rb`.
- [x] Run `cd packages/better_auth-stripe && rbenv exec bundle exec rake test`.
- [x] If core files are edited, run the affected `packages/better_auth` tests too. No core files were edited for this task.

---

## Upstream Test Parity Matrix

Status legend: `covered` means translated to Ruby directly or covered by a grouped Ruby integration test. `skip-ruby` means the upstream test is TypeScript type/client compile behavior and has no Ruby runtime equivalent.

### `upstream/packages/stripe/test/utils.test.ts`

- [x] covered: `should escape double quotes`
- [x] covered: `should handle strings without quotes`
- [x] covered: `should escape multiple quotes`
- [x] covered: `should return item and plan for single-item subscriptions`
- [x] covered: `should return undefined for empty items`
- [x] covered: `should return item without plan for unmatched single-item`
- [x] covered: `should return matching plan item from multi-item subscription`
- [x] covered: `should return undefined when no plan matches in multi-item`
- [x] covered: `should match by lookup key`

### `upstream/packages/stripe/test/metadata.test.ts`

- [x] covered: `drops __proto__ from user metadata on customerMetadata.set`
- [x] covered: `drops constructor and prototype from user metadata on customerMetadata.set`
- [x] covered: `drops __proto__ from user metadata on subscriptionMetadata.set`
- [x] covered: `internal fields always take precedence over user metadata`

### `upstream/packages/stripe/test/stripe.test.ts`

- [x] skip-ruby: `should api endpoint exists`
- [x] skip-ruby: `should have subscription endpoints`
- [x] skip-ruby: `should infer plugin schema fields on user type`
- [x] skip-ruby: `should infer plugin schema fields alongside additional user fields`
- [x] covered: `customerMetadata.set protects internal fields`
- [x] covered: `customerMetadata.get extracts typed fields`
- [x] covered: `subscriptionMetadata.set protects internal fields`
- [x] covered: `subscriptionMetadata.get extracts typed fields`
- [x] covered: `should create a customer on sign up`
- [x] covered: `should create a subscription`
- [x] covered: `should not allow cross-user subscriptionId operations (upgrade/cancel/restore)`
- [x] covered: `should pass metadata to subscription when upgrading`
- [x] covered: `should list active subscriptions`
- [x] covered: `should return annualDiscountPriceId when subscription billingInterval is year`
- [x] covered: `should handle subscription webhook events`
- [x] covered: `should handle subscription webhook events with trial`
- [x] covered: `should handle subscription deletion webhook`
- [x] covered: `should handle customer.subscription.created webhook event`
- [x] covered: `should store billingInterval as year for annual subscriptions`
- [x] covered: `should return billingInterval in subscription.list() response`
- [x] covered: `should not create duplicate subscription if already exists`
- [x] covered: `should skip subscription creation when user not found`
- [x] covered: `should skip subscription creation when plan not found`
- [x] covered: `should skip creating subscription when metadata.subscriptionId exists`
- [x] covered: `should execute subscription event handlers`
- [x] covered: `should return updated subscription in onSubscriptionUpdate callback`
- [x] covered: `should sync stripeScheduleId from webhook when schedule is present`
- [x] covered: `should clear stripeScheduleId from webhook when schedule is removed`
- [x] covered: `should clear stripeScheduleId on subscription deleted webhook`
- [x] covered: `should allow seat upgrades for the same plan`
- [x] covered: `should prevent duplicate subscriptions with same plan and same seats`
- [x] covered: `should allow upgrade from monthly to annual billing for the same plan`
- [x] covered: `should only call Stripe customers.create once for signup and upgrade`
- [x] covered: `should create billing portal session`
- [x] covered: `should create billing portal session for an existing custom referenceId`
- [x] covered: `should not update personal subscription when upgrading with a custom referenceId`
- [x] covered: `should prevent multiple free trials for the same user`
- [x] covered: `should upgrade existing subscription instead of creating new one`
- [x] covered: `should prevent multiple free trials across different plans`
- [x] covered: `should update stripe customer email when user email changes`
- [x] covered: `should call getCustomerCreateParams and merge with default params`
- [x] covered: `should use getCustomerCreateParams to add custom address`
- [x] covered: `should properly merge nested objects using defu`
- [x] covered: `should work without getCustomerCreateParams`
- [x] covered: `should handle invalid webhook signature with constructEventAsync`
- [x] covered: `should reject webhook request without stripe-signature header`
- [x] covered: `should handle constructEventAsync returning null/undefined`
- [x] covered: `should handle async errors in webhook event processing`
- [x] covered: `should successfully process webhook with valid async signature verification`
- [x] covered: `should call constructEventAsync with exactly 3 required parameters`
- [x] covered: `should support Stripe v18 with sync constructEvent method`
- [x] covered: `should support flexible limits types`
- [x] covered: `should NOT create duplicate customer when email already exists in Stripe`
- [x] covered: `should CREATE customer only when user has no stripeCustomerId and none exists in Stripe`
- [x] covered: `should NOT return organization customer when searching for user customer with same email`
- [x] covered: `should find existing user customer even when organization customer with same email exists`
- [x] covered: `should create organization customer with customerType metadata`
- [x] covered: `should fall back to customers.list when customers.search is unavailable (user signup)`
- [x] covered: `should fall back to customers.list when customers.search is unavailable (user upgrade)`
- [x] covered: `should sync cancelAtPeriodEnd and canceledAt when user cancels via Billing Portal (at_period_end mode)`
- [x] covered: `should sync cancelAt when subscription is scheduled to cancel at a specific date`
- [x] covered: `should set status=canceled and endedAt when subscription is immediately canceled`
- [x] covered: `should set endedAt when cancel_at_period_end subscription reaches period end`
- [x] covered: `should check all subscriptions for trial history even when processing a specific incomplete subscription`
- [x] covered: `should propagate trial data from Stripe event on subscription.deleted`
- [x] covered: `should propagate trial data from Stripe event on subscription.updated`
- [x] covered: `should prevent trial abuse after subscription canceled during trial`
- [x] covered: `should clear cancelAtPeriodEnd when restoring a cancel_at_period_end subscription`
- [x] covered: `should clear cancelAt when restoring a cancel_at (specific date) subscription`
- [x] covered: `should release schedule and clear stripeScheduleId when restoring a pending schedule`
- [x] covered: `should reject restore when no pending cancel and no pending schedule`
- [x] covered: `should sync from Stripe when cancel request fails because subscription is already canceled`
- [x] covered: `should pass when no explicit referenceId is provided`
- [x] covered: `should pass when referenceId equals user id`
- [x] covered: `should reject when authorizeReference is not defined but other referenceId is provided`
- [x] covered: `should reject another user's referenceId when authorizeReference returns false`
- [x] covered: `should allow another user's referenceId when authorizeReference returns true`
- [x] covered: `should reject when authorizeReference is not defined`
- [x] covered: `should reject when no referenceId or activeOrganizationId`
- [x] covered: `should reject when authorizeReference returns false`
- [x] covered: `should pass when authorizeReference returns true`
- [x] covered: `should upgrade existing active subscription even when canceled subscription exists for same referenceId`
- [x] covered: `should schedule plan change at period end when scheduleAtPeriodEnd is true`
- [x] covered: `should release existing schedule before scheduling a new one`
- [x] covered: `should release existing schedule before immediate upgrade`
- [x] covered: `should not release schedules created outside the plugin`
- [x] covered: `should swap line item prices when upgrading immediately`
- [x] covered: `should swap line item prices in scheduled phase`
- [x] covered: `should add new line items when upgrading to a plan with more items`
- [x] covered: `should remove extra line items when downgrading to a plan with fewer items`
- [x] covered: `should not duplicate line items already present in the subscription (immediate)`
- [x] covered: `should not duplicate line items already present in scheduled phase`
- [x] covered: `should update subscription via checkoutSessionId and redirect`
- [x] covered: `should redirect without update when checkoutSessionId is missing`
- [x] covered: `should replace {CHECKOUT_SESSION_ID} placeholder in callbackURL with actual session ID`
- [x] covered: `should redirect when checkout session retrieval fails`
- [x] covered: `should not include quantity for metered base price in checkout session`
- [x] covered: `should still include quantity for licensed base price in checkout session`
- [x] covered: `should not include quantity for metered price during billing portal upgrade`
- [x] covered: `should not include quantity for metered price during direct subscription upgrade`
- [x] covered: `should not include quantity for metered price during scheduled upgrade`

### `upstream/packages/stripe/test/stripe-organization.test.ts`

- [x] covered: `should create a Stripe customer for organization when upgrading subscription`
- [x] covered: `should use existing Stripe customer ID from organization`
- [x] covered: `should call getCustomerCreateParams when creating org customer`
- [x] covered: `should create billing portal for organization`
- [x] covered: `should cancel subscription for organization`
- [x] covered: `should restore subscription for organization`
- [x] covered: `should list subscriptions for organization`
- [x] covered: `should handle webhook for organization subscription created from dashboard`
- [x] covered: `should not allow cross-organization subscription operations`
- [x] covered: `should reject organization subscription when authorizeReference is not configured`
- [x] covered: `should keep user and organization subscriptions separate`
- [x] covered: `should handle customer.subscription.updated webhook for organization`
- [x] covered: `should handle customer.subscription.updated webhook with cancellation for organization`
- [x] covered: `should handle customer.subscription.deleted webhook for organization`
- [x] covered: `should return ORGANIZATION_NOT_FOUND when upgrading for non-existent organization`
- [x] covered: `should return error when Stripe customer creation fails for organization`
- [x] covered: `should return error when getCustomerCreateParams callback throws`
- [x] covered: `should call onSubscriptionCreated callback for organization subscription from dashboard`
- [x] covered: `should not match user customer with organizationId in metadata during org customer lookup`
- [x] covered: `should sync organization name to Stripe customer on update`
- [x] covered: `should block organization deletion when active subscription exists`
- [x] covered: `should allow organization deletion when no active subscription`

### `upstream/packages/stripe/test/seat-based-billing.test.ts`

- [x] covered: `should create checkout with both base plan and seat line items`
- [x] covered: `should use actual member count as seat quantity`
- [x] covered: `should include additional line items in checkout`
- [x] covered: `should not include extra line items when plan has none`
- [x] covered: `should not duplicate base price in line_items`
- [x] covered: `should swap seat item when upgrading to a plan with different seat pricing`
- [x] covered: `should use custom prorationBehavior from plan config`
- [x] covered: `should skip seat item swap when seat pricing is unchanged`
- [x] covered: `should not duplicate subscription item when upgrading between seat-only plans`
- [x] covered: `should sync seat quantity when a member accepts an invitation`
- [x] covered: `should sync seat quantity when a member is removed`
- [x] covered: `should use custom prorationBehavior on member removal`
- [x] covered: `should persist seat count on subscription creation`
- [x] covered: `should update seat count on subscription update`
