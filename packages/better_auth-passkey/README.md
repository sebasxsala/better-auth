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
    BetterAuth::Plugins.passkey(
      rp_id: "localhost",
      rp_name: "Example App",
      origin: "http://localhost:3000"
    )
  ]
)
```

## Options

`BetterAuth::Plugins.passkey` accepts Ruby `snake_case` options:

- `rp_id`: WebAuthn relying party ID. Defaults to the configured `base_url` host.
- `rp_name`: WebAuthn relying party name. Defaults to the Better Auth app name.
- `origin`: allowed WebAuthn origin or array of origins.
- `authenticator_selection`: supports `resident_key`, `user_verification`, and `authenticator_attachment`.
- `advanced.web_authn_challenge_cookie`: challenge cookie name. Defaults to `better-auth-passkey`.
- `registration`: supports `require_session`, `resolve_user`, `after_verification`, and `extensions`.
- `authentication`: supports `after_verification` and `extensions`.
- `schema`: deep-merged schema overrides. The built-in SQL table remains `passkeys`, matching the Ruby adapter convention.

HTTP routes and wire JSON keys are kept compatible with upstream Better Auth passkey server behavior. Ruby method names and configuration keys remain idiomatic `snake_case`.

## Passkey-first registration

Use `require_session: false` to register a passkey before a session exists:

```ruby
BetterAuth::Plugins.passkey(
  registration: {
    require_session: false,
    resolve_user: lambda do |data|
      invitation = Invitations.verify!(data.fetch(:context))
      {
        id: invitation.user_id,
        name: invitation.email,
        display_name: invitation.name,
        email: invitation.email
      }
    end,
    after_verification: lambda do |data|
      Audit.passkey_registered!(
        user_id: data.fetch(:user).fetch(:id),
        context: data.fetch(:context)
      )
      nil
    end
  }
)
```

Pass `context` when generating registration options:

```ruby
auth.api.generate_passkey_registration_options(query: { context: invitation_token })
```

During passkey-first registration, `after_verification` may return `{ user_id: "..." }` to attach the credential to a concrete user. During session-required registration, switching users is rejected.

## WebAuthn extensions

```ruby
BetterAuth::Plugins.passkey(
  registration: {
    extensions: { credProps: true }
  },
  authentication: {
    extensions: ->(_data) { { hmacGetSecret: true } }
  }
)
```

## Browser client scope

This gem provides server WebAuthn routes. It does not ship the upstream browser-only `@better-auth/passkey/client` helper, `passkeyClient`, `startRegistration`, `startAuthentication`, conditional UI, autofill, or extension-result handling. Use the browser WebAuthn APIs directly or wrap them in application JavaScript.

## WebAuthn configuration

The plugin uses `WebAuthn::RelyingParty` per request for `rp_id`, `rp_name`, and allowed origins. It does not mutate global `WebAuthn.configuration`, so multiple Better Auth instances can use different relying-party settings in the same Ruby process.

## Notes

This package depends on the maintained `webauthn` gem. Keeping passkeys outside `better_auth` avoids installing WebAuthn dependencies for applications that do not use passkeys.
