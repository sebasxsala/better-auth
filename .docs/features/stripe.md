# Feature: Stripe Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/stripe/src/index.ts`, `upstream/packages/stripe/src/routes.ts`, `upstream/packages/stripe/src/schema.ts`, `upstream/packages/stripe/src/hooks.ts`, `upstream/packages/stripe/src/middleware.ts`, `upstream/packages/stripe/src/metadata.ts`, `upstream/packages/stripe/src/utils.ts`, `upstream/packages/stripe/src/error-codes.ts`, `upstream/packages/stripe/test/stripe.test.ts`, `upstream/packages/stripe/test/stripe-organization.test.ts`

## Summary

Adds `BetterAuth::Plugins.stripe` with injected Stripe client support, customer creation/de-duplication, subscription checkout, list/cancel/restore, billing portal, webhook handling, state synchronization, and organization mode.

## Ruby Adaptation

- Implemented inside the core gem as a plugin with no required Stripe gem dependency.
- Uses an injected `stripe_client` object so apps can provide the official Stripe SDK, a wrapper, or a fake in tests.
- Adds `user.stripeCustomerId`; adds `subscription` when subscription mode is enabled, including `stripeScheduleId`; adds `organization.stripeCustomerId` when organization mode is configured.
- Adds `/subscription/upgrade`, `/subscription/cancel`, `/subscription/cancel/callback`, `/subscription/restore`, `/subscription/list`, `/subscription/success`, `/subscription/billing-portal`, and `/stripe/webhook`.
- Preserves upstream route JSON keys while accepting Ruby-style snake_case options.
- Supports public metadata helpers, custom customer-create params, user and organization customer-create callbacks, checkout session params/options, lookup-key price resolution with upstream error handling, trial-start callbacks, synchronous webhook construction, and async-style injected webhook clients when provided by the application wrapper.

## Key Differences

- The Ruby package does not depend directly on the Stripe gem. Applications inject the official Stripe Ruby SDK client, or any compatible wrapper, via `stripe_client`.
- Webhook verification delegates to the injected client through `webhooks.construct_event`; wrappers can expose `construct_event_async` for async-style parity. The injected client receives the required payload/signature/secret argument shape.
- Organization mode requires the organization plugin for real organization records and requires `subscription.authorize_reference` for organization reference authorization, matching upstream safety checks.
- Native/browser Stripe client helpers are TypeScript client concerns and remain outside the Ruby server surface.

## Covered Behavior

- Checkout creation, billing portal creation, subscription list/cancel/cancel callback/restore/success routes.
- Reference authorization for user and organization subscriptions, including cross-reference rejection.
- Plan lookup, annual price IDs, lookup-key resolution failures, seat quantity changes, organization `seatPriceId` billing with separate base/seat line items, duplicate active subscription rejection, `scheduleAtPeriodEnd` subscription schedules, one-trial-per-reference protection across plans, and `free_trial.on_trial_start` callbacks.
- Customer de-duplication by Stripe search, custom customer-create params, user and organization `on_customer_create` callbacks, user email sync, organization customer creation, organization name sync, and active-subscription deletion guard.
- Public customer/subscription metadata helpers that protect internal fields while preserving custom metadata keys.
- Checkout customization through `get_checkout_session_params`, including additional session params, request options, custom metadata, lookup-key resolved prices, and rejection when no price ID can be resolved.
- Webhook signature errors, Stripe v18-style sync construction, async-style construction, unknown-event callback forwarding, checkout completion, dashboard-created subscriptions, duplicate-created event ordering, updates, pending cancellation, deletion, and lifecycle callbacks.
- Subscription state transitions for incomplete, active, trialing, pending cancel, restored, and canceled subscriptions.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_organization_test.rb
```
