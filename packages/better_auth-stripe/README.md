# better_auth-stripe

Stripe subscription and customer plugin package for Better Auth Ruby.

## Installation

Add the gem and require the package before configuring the plugin:

```ruby
gem "better_auth-stripe"
```

```ruby
require "better_auth/stripe"

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: :memory,
  plugins: [
    BetterAuth::Plugins.stripe(
      stripe_api_key: ENV.fetch("STRIPE_SECRET_KEY"),
      stripe_webhook_secret: ENV.fetch("STRIPE_WEBHOOK_SECRET")
    )
  ]
)
```

## Notes

This package depends on the official `stripe` gem. Keeping Stripe outside `better_auth` avoids installing Stripe SDK dependencies for applications that do not use billing.

Pass `stripe_client:` when you need a custom Stripe client, Stripe Connect behavior, or a test double.
