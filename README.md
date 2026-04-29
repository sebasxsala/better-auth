<p align="center">
  <h1 align="center">Better Auth Ruby</h1>
  <p align="center">
    A Ruby and Rack port of Better Auth, with Rails, Sinatra, Hanami, storage adapters, and server-side plugin packages.
    <br />
    <a href="https://better-auth.com"><strong>Upstream Better Auth</strong></a>
    -
    <a href="https://better-auth-ruby.vercel.app/">Ruby docs</a>
    -
    <a href="https://github.com/sebasxsala/better-auth/issues">Issues</a>
  </p>
  <p align="center">
    <a href="https://rubygems.org/gems/better_auth"><img alt="Gem" src="https://img.shields.io/gem/v/better_auth?style=flat&colorA=111111&colorB=111111"></a>
    <a href="https://github.com/sebasxsala/better-auth/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/sebasxsala/better-auth?style=flat&colorA=111111&colorB=111111"></a>
  </p>
</p>

## What This Is

Better Auth Ruby ports the server runtime of [Better Auth](https://github.com/better-auth/better-auth) from TypeScript to Ruby. The target is upstream-compatible HTTP behavior with idiomatic Ruby internals:

- Rack-first core that can run without Rails.
- Rails, Sinatra, and Hanami adapters.
- SQL, ActiveRecord, MongoDB, Redis secondary storage, and memory adapters.
- Server-side plugin parity for the Better Auth plugins that make sense in Ruby.

The upstream project is tracked as a submodule in [`upstream/`](upstream/). Feature parity notes live in [`.docs/features/`](.docs/features/) and implementation plans live in [`.docs/plans/`](.docs/plans/).

This project is active work. Many server flows are implemented and tested, but exact upstream parity is not complete across every route, adapter edge case, OpenAPI schema, and OAuth/social linking rule.

## Support Snapshot

Current target: upstream Better Auth `v1.6.9`.

| Metric | Value | How to read it |
| --- | ---: | --- |
| Server-relevant upstream test suites | 125 | Upstream suites relevant to the Ruby server runtime. |
| Local Ruby test/spec suites | 98 | Minitest and RSpec files across all local packages. Local suites are sometimes consolidated, so this is a footprint metric, not a one-to-one parity claim. |
| Static local test examples | 981 | `def test_...` plus RSpec `it`/`specify` examples found in the repo. |
| Test-suite support footprint | 78% | `98 / 125`. This estimates how much upstream server surface has corresponding Ruby test coverage. |
| Feature support inventory | 52% complete, 37% partial, 11% not started | 31 complete, 1 ported, 23 partial, 7 not started. |
| Weighted support estimate | 70% | Complete/ported areas count as 1, partial areas count as 0.5. This is the conservative top-line support number. |

Use the 70% figure when asking "how much of Better Auth is supported?" Use the 78% figure when asking "how much of the upstream server test footprint has a Ruby counterpart?"

## Install

### Rails

```ruby
# Gemfile
gem "better_auth-rails"
```

```bash
bundle install
bin/rails generate better_auth:install
```

```ruby
# config/routes.rb
Rails.application.routes.draw do
  better_auth
end
```

### Rack

```ruby
# Gemfile
gem "better_auth"
```

```ruby
require "better_auth"

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  base_url: "http://localhost:3000",
  database: BetterAuth::Adapters::Memory.new
)

run auth
```

### Sinatra

```ruby
# Gemfile
gem "better_auth-sinatra"
```

```ruby
require "sinatra/base"
require "better_auth/sinatra"

class App < Sinatra::Base
  register BetterAuth::Sinatra

  better_auth at: "/api/auth" do |config|
    config.secret = ENV.fetch("BETTER_AUTH_SECRET")
    config.base_url = ENV.fetch("BETTER_AUTH_URL")
    config.database = ->(options) {
      BetterAuth::Adapters::Postgres.new(options, url: ENV.fetch("DATABASE_URL"))
    }
  end
end
```

## Packages

| Package | Purpose | Install | Status |
| --- | --- | --- | --- |
| [`better_auth`](packages/better_auth/) | Rack core: auth routes, sessions, cookies, adapters, plugin system, and built-in server plugins. | `gem "better_auth"` | Partial |
| [`better_auth-rails`](packages/better_auth-rails/) | Rails mount helpers, ActiveRecord adapter, controller helpers, migrations, and generators. | `gem "better_auth-rails"` | Partial |
| [`better_auth-sinatra`](packages/better_auth-sinatra/) | Sinatra extension, Rack mounting, helpers, and migration tasks. | `gem "better_auth-sinatra"` | Partial |
| [`better_auth-hanami`](packages/better_auth-hanami/) | Hanami integration, action helpers, Sequel adapter, migrations, and generators. | `gem "better_auth-hanami"` | Partial |
| [`better_auth-redis-storage`](packages/better_auth-redis-storage/) | Redis secondary storage for sessions, active-session indexes, verification-like state, and rate limits. | `gem "better_auth-redis-storage"` | Partial |
| [`better_auth-mongo-adapter`](packages/better_auth-mongo-adapter/) | MongoDB database adapter using the official `mongo` gem. | `gem "better_auth-mongo-adapter"` | Partial |
| [`better_auth-api-key`](packages/better_auth-api-key/) | API key plugin package. | `gem "better_auth-api-key"` | Supported |
| [`better_auth-passkey`](packages/better_auth-passkey/) | Passkey/WebAuthn plugin package. | `gem "better_auth-passkey"` | Supported |
| [`better_auth-sso`](packages/better_auth-sso/) | OIDC and SAML SSO plugin package. | `gem "better_auth-sso"` | Not supported |
| [`better_auth-scim`](packages/better_auth-scim/) | SCIM v2 provisioning plugin package. | `gem "better_auth-scim"` | Supported |
| [`better_auth-stripe`](packages/better_auth-stripe/) | Stripe billing plugin package. | `gem "better_auth-stripe"` | Supported |
| [`better_auth-oauth-provider`](packages/better_auth-oauth-provider/) | OAuth 2.0/OIDC provider plugin package. | `gem "better_auth-oauth-provider"` | Supported |

Status meanings:

- `Supported`: Ruby server behavior is implemented with local tests.
- `Partial`: The main path works, but upstream edge cases, adapter matrices, or exact schema snapshots are still in progress.
- `Not supported`: Not implemented or intentionally outside Ruby server scope.

## Core Support

| Area | Status | What works | Main gaps |
| --- | --- | --- | --- |
| Rack auth factory and API object | Partial | `BetterAuth.auth(...)`, Rack calls, direct server API access, error-code merge, plugin initialization. | Some upstream context/init edge cases and client-facing API conveniences. |
| Endpoint router and middleware | Partial | Rack routing, route params, hooks, plugin middleware, redirects, cookies, origin checks, conflict logging, rate-limit hooks. | Full upstream endpoint conversion matrix and database-backed rate-limit parity. |
| Email/password auth | Partial | Sign-up, sign-in, password hashing, verification requirement, reset password, set/change password, delete/update user. | Full email-change state machine, sender-failure no-enumeration parity, and several callback URL edge cases. |
| Social OAuth flow | Partial | OAuth authorization URLs, callbacks, social sessions, token storage, account linking/unlinking, refresh/access-token routes. | Trusted-provider linking rules, account cookies, encrypted OAuth tokens, and some `disableSignUp`/callback variants. |
| Sessions and cookies | Partial | Signed cookies, cache cookies, chunking, deletion, revocation routes, secondary storage, Redis-backed session storage. | Full upstream session/cache matrix and account-cookie cleanup behavior. |
| CSRF and trusted origins | Partial | Origin checks, trusted origins, proxy-aware IP handling, selected callback validation. | Callback-bearing GET route parity is still being tightened. |
| Database schema and hooks | Supported | Base schema, plugin schema merge, SQL/Rails migration generation, adapter hooks, logical Better Auth field names. | Adapter-specific edge cases remain in adapter rows. |
| Memory adapter | Supported | Development/test adapter. | Not intended for production persistence. |
| SQL adapters | Partial | PostgreSQL, MySQL, SQLite, and MSSQL adapter wrappers plus DDL generation. | Full upstream adapter contract, exhaustive joins, affected-row semantics, and some input filtering. |
| MongoDB adapter | Partial | External package with document storage, ObjectId conversion, joins, transactions, and auth-route persistence. | Full upstream adapter contract parity is still expanding. |
| Rails ActiveRecord adapter | Partial | ActiveRecord persistence, migrations, mounting helpers, controller helpers, and generators. | Broader request specs and full adapter contract parity. |
| OpenAPI | Partial | OpenAPI 3.1.1 metadata, route/model inventory, security schemes, servers, selected request bodies, path params, reference HTML. | Exact upstream snapshot parity and rich schemas for many base paths. |

## Social Providers

Built-in provider factories:

| Provider | Status | Notes |
| --- | --- | --- |
| Apple, Atlassian, Cognito, Discord, Dropbox, Facebook, Figma, GitHub, GitLab, Google, Hugging Face, Kakao, Kick, Line, Linear, LinkedIn, Microsoft Entra ID, Naver, Notion, Paybin, PayPal, Polar, Railway, Reddit, Roblox, Salesforce, Slack, Spotify, TikTok, Twitch, Twitter/X, Vercel, VK, WeChat, Zoom | Supported | Provider factories and OAuth/OpenID profile mapping are implemented. |

Use `BetterAuth::Plugins.generic_oauth` for custom providers that are not part of the built-in set.

## Plugin Support

| Plugin | Status | Coverage |
| --- | --- | --- |
| Access control | Supported | Roles, statements, permissions, resource/action checks. |
| Additional fields | Supported | Schema extension and route integration. |
| Admin | Supported | User management, sessions, roles, bans, impersonation, destructive endpoints, permissions. |
| Anonymous | Supported | Anonymous sign-in/delete and link cleanup. |
| API key | Supported | Creation, verification, hashing, expiration, quotas, metadata, permissions, storage modes, API-key sessions. |
| Bearer | Supported | Bearer session resolution, signed/unsigned token modes, cookie fallback. |
| Captcha | Supported | reCAPTCHA, hCaptcha, Turnstile, CaptchaFox, protected routes, score checks. |
| Custom session | Supported | Custom `/get-session` shaping and optional multi-session list mutation. |
| Device authorization | Supported | Device/user codes, polling, slow-down, approval/denial, token exchange, verification URI behavior. |
| Email OTP | Supported | Send/check/verify/sign-in/password-reset/change-email flows, attempts, storage modes, rate limits. |
| Expo server integration | Supported | Server-side authorization proxy, origin override, trusted deep-link cookie transfer. |
| Generic OAuth | Supported | Custom OAuth sign-in/callback/link flows, DB and cookie state, dynamic params, issuer checks, token/userinfo exchange. |
| Have I Been Pwned | Supported | SHA-1 k-anonymity lookup and protected password routes. |
| JWT/JWKS | Supported | EdDSA default, RSA/ECDSA algorithms, JWKS publication, rotation helpers, remote verification, `set-auth-jwt`. |
| Last login method | Supported | Email, SIWE, social, generic OAuth cookie/user-field updates. |
| Magic link | Supported | Send/verify, redirects/errors, signup, latest-token verification, token storage modes. |
| MCP | Supported | OAuth metadata, registration, authorization-code PKCE, token refresh, userinfo, JWKS, helper challenge headers. |
| Multi-session | Supported | Device sessions, active switching, replacement, revocation, sign-out cleanup. |
| OAuth proxy | Supported | Callback rewriting, encrypted cross-origin cookie forwarding, validation, stateless state restoration. |
| OAuth provider | Supported | Metadata, registration, clients, consent, auth code, client credentials, tokens, introspection, revocation, userinfo, logout. |
| OIDC provider | Supported | Discovery, prompt/max-age, registration, consent, token flows, userinfo, logout, client-secret storage modes. |
| One tap | Supported | Google ID-token callback, account reuse/linking, disabled signup, session cookies. |
| One-time token | Supported | Generate/verify, single-use, expiration, cookie behavior, storage modes, `set-ott`. |
| OpenAPI | Partial | Metadata, route inventory, models, security, selected schemas, reference HTML. Exact upstream snapshot parity is still in progress. |
| Organization | Supported | Org/member CRUD, invitations, teams, roles, hooks, permissions, schema migrations. |
| Passkey | Supported | WebAuthn registration/authentication, challenge cookies, credential management, schema output. |
| Phone number | Supported | OTP send/verify, sign-in/sign-up, updates, reset password, attempt limits, validation hooks. |
| SCIM | Supported | Token envelopes, Bearer middleware, metadata, user CRUD, provider management, mappings, filters, PATCH, org enforcement. |
| SIWE | Supported | Nonce, wallet sign-in, ENS hook, account/session creation, EIP-55 casing, multi-chain wallets. |
| SSO | Not supported | Package exists, but this README does not mark it as supported yet. |
| Stripe | Supported | Checkout, portal, webhooks, subscription state transitions, seats, trials, org subscriptions, metadata helpers. |
| Two-factor | Supported | TOTP, OTP, backup codes, trusted devices, disable/recovery, post-login verification. |
| Username | Supported | Username sign-up/sign-in, availability, normalization, validation, duplicates, leak-prevention behavior. |

## Development

### Clone and verify everything

```bash
git clone --recursive https://github.com/sebasxsala/better-auth.git
cd better-auth
make install
make ci
```

### Work on one package

```bash
cd packages/better_auth
bundle install
bundle exec rake test
```

### Package test commands

| Package | Command |
| --- | --- |
| Core | `cd packages/better_auth && bundle exec rake test` |
| Rails | `cd packages/better_auth-rails && bundle exec rspec` |
| Sinatra | `cd packages/better_auth-sinatra && bundle exec rspec` |
| Hanami | `cd packages/better_auth-hanami && bundle exec rspec` |
| API key | `cd packages/better_auth-api-key && bundle exec rake` |
| Mongo adapter | `cd packages/better_auth-mongo-adapter && bundle exec rake` |
| OAuth provider | `cd packages/better_auth-oauth-provider && bundle exec rake` |
| Passkey | `cd packages/better_auth-passkey && bundle exec rake` |
| Redis storage | `cd packages/better_auth-redis-storage && bundle exec rake` |
| SCIM | `cd packages/better_auth-scim && bundle exec rake` |
| SSO | `cd packages/better_auth-sso && bundle exec rake` |
| Stripe | `cd packages/better_auth-stripe && bundle exec rake` |

Database-backed tests may require Docker services from the repo root:

```bash
docker compose up -d
```

## Documentation

The upstream docs app has been copied into [`docs/`](docs/) and is being adapted for Ruby, Rack, Rails, Sinatra, and Hanami. Pages that still contain upstream TypeScript examples include a warning callout.

Ruby-first starter pages currently live under:

- [`docs/content/docs/introduction.mdx`](docs/content/docs/introduction.mdx)
- [`docs/content/docs/installation.mdx`](docs/content/docs/installation.mdx)
- [`docs/content/docs/basic-usage.mdx`](docs/content/docs/basic-usage.mdx)
- [`docs/content/docs/concepts/database.mdx`](docs/content/docs/concepts/database.mdx)
- [`docs/content/docs/integrations/rack.mdx`](docs/content/docs/integrations/rack.mdx)
- [`docs/content/docs/integrations/rails.mdx`](docs/content/docs/integrations/rails.mdx)
- [`docs/content/docs/integrations/sinatra.mdx`](docs/content/docs/integrations/sinatra.mdx)

## Repository Layout

```txt
better-auth/
|-- upstream/                       # Better Auth TypeScript submodule
|-- docs/                           # Adapted docs app
|-- packages/
|   |-- better_auth/                # Rack core, Minitest
|   |-- better_auth-api-key/        # API key plugin package
|   |-- better_auth-hanami/         # Hanami adapter, RSpec
|   |-- better_auth-mongo-adapter/  # MongoDB adapter package
|   |-- better_auth-oauth-provider/ # OAuth provider plugin package
|   |-- better_auth-passkey/        # Passkey/WebAuthn plugin package
|   |-- better_auth-rails/          # Rails adapter, RSpec
|   |-- better_auth-redis-storage/  # Redis secondary storage package
|   |-- better_auth-scim/           # SCIM plugin package
|   |-- better_auth-sinatra/        # Sinatra adapter, RSpec
|   |-- better_auth-sso/            # SSO plugin package
|   `-- better_auth-stripe/         # Stripe plugin package
|-- .docs/
|   |-- features/                   # Feature parity notes
|   `-- plans/                      # Port implementation plans
|-- Gemfile
|-- Rakefile
`-- Makefile
```

## Git Workflow

- `canary`: day-to-day development; open PRs here.
- `main`: stable line; release tags are cut from here.
- `upstream/`: source-of-truth submodule; do not edit upstream source as part of Ruby work.

```bash
git checkout canary
git pull origin canary
git checkout -b feat/my-change
# commit changes
git push -u origin feat/my-change
# open a PR to canary
```

## Releases

Releases are automated with GitHub Actions when a package version tag is pushed. Each gem is versioned independently; only bump the gem being released. The Rails adapter publishes both `better_auth-rails` and the compatibility alias `better_auth_rails`.

Local release validation:

```bash
make release-check
```

## Contributing

1. Fork the repo.
2. Branch from `canary`.
3. Read [`AGENTS.md`](AGENTS.md) and the package-specific instructions before editing.
4. Check upstream source and upstream tests for behavior.
5. Run the relevant package tests, or `make ci` for the full repo, before pushing.
6. Open a PR to `canary`.

## Security

Report vulnerabilities to security@openparcel.dev. See [`SECURITY.md`](SECURITY.md).

## License

[MIT License](LICENSE.md)
