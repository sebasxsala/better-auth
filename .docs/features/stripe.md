# Feature: Stripe Plugin

**Upstream Reference:** `upstream/packages/stripe/src/index.ts`, `upstream/packages/stripe/src/routes.ts`, `upstream/packages/stripe/src/schema.ts`, `upstream/packages/stripe/src/hooks.ts`, `upstream/packages/stripe/src/middleware.ts`, `upstream/packages/stripe/src/metadata.ts`, `upstream/packages/stripe/src/utils.ts`, `upstream/packages/stripe/src/error-codes.ts`, `upstream/packages/stripe/test/stripe.test.ts`, `upstream/packages/stripe/test/stripe-organization.test.ts`

## Summary

Adds `BetterAuth::Plugins.stripe` with injected Stripe client support, customer creation on sign-up, subscription checkout, list/cancel/restore, billing portal, webhook handling, and guarded organization mode.

## Ruby Adaptation

- Implemented inside the core gem as a plugin with no required Stripe gem dependency.
- Uses an injected `stripe_client` object so apps can provide the official Stripe SDK, a wrapper, or a fake in tests.
- Adds `user.stripeCustomerId`; adds `subscription` when subscription mode is enabled; adds `organization.stripeCustomerId` when organization mode is configured.
- Adds `/subscription/upgrade`, `/subscription/cancel`, `/subscription/cancel/callback`, `/subscription/restore`, `/subscription/list`, `/subscription/success`, `/subscription/billing-portal`, and `/stripe/webhook`.

## Key Differences

- Organization subscription operations are guarded with a clear error until the organization plugin is ported.
- Webhook verification delegates to the injected client when it exposes `webhooks.construct_event`.
- Full plan/seat/trial abuse and every Stripe event edge case remains partial; current tests cover the server contract and persistence path.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/stripe_organization_test.rb
```
