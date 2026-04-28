# better_auth-api-key

API key plugin package for Better Auth Ruby.

## Installation

Add the gem and require the package before configuring the plugin:

```ruby
gem "better_auth-api-key"
```

```ruby
require "better_auth/api_key"

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: :memory,
  plugins: [
    BetterAuth::Plugins.api_key
  ]
)
```

## Notes

This package matches upstream's separate `@better-auth/api-key` package boundary. The Ruby plugin keeps the public `BetterAuth::Plugins.api_key` entrypoint, while core `better_auth` only provides a compatibility shim.
