# better_auth-passkey

Passkey/WebAuthn plugin package for Better Auth Ruby.

## Installation

Add the gem and require the package before configuring the plugin:

```ruby
gem "better_auth-passkey"
```

```ruby
require "better_auth/passkey"

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: :memory,
  plugins: [
    BetterAuth::Plugins.passkey
  ]
)
```

## Notes

This package depends on the maintained `webauthn` gem. Keeping passkeys outside `better_auth` avoids installing WebAuthn dependencies for applications that do not use passkeys.
