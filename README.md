<p align="center">
  <h2 align="center">
    Better Auth Ruby
  </h2>

  <p align="center">
    The Ruby/Rack port of Better Auth
    <br />
    <a href="https://better-auth.com"><strong>Learn more about upstream Better Auth</strong></a>
    <br />
    <br />
    <a href="https://better-auth-ruby.vercel.app/">Website</a>
    ·
    <a href="https://github.com/sebasxsala/better-auth/issues">Issues</a>
  </p>

[![Gem](https://img.shields.io/gem/v/better_auth?style=flat&colorA=000000&colorB=000000)](https://rubygems.org/gems/better_auth)
[![GitHub stars](https://img.shields.io/github/stars/sebasxsala/better-auth?style=flat&colorA=000000&colorB=000000)](https://github.com/sebasxsala/better-auth/stargazers)
</p>

## About

Better Auth Ruby is a Ruby port of [Better Auth](https://github.com/better-auth/better-auth), the framework-agnostic authentication and authorization library from the TypeScript ecosystem.

The goal is upstream-compatible HTTP behavior with idiomatic Ruby internals: Rack first, Rails friendly, and tested against the upstream Better Auth source and test suite as the source of truth. This repository keeps the upstream project as a submodule under `upstream/` and tracks port status in `.docs/features/` and `.docs/plans/`.

This port is active work. Many server-side flows are implemented, but not every upstream edge case, adapter dialect, or TypeScript-only API has full parity yet.

## Packages

| Gem | Description | Install |
| --- | --- | --- |
| [`better_auth`](packages/better_auth/) | Framework-agnostic Rack core. Auth routes, sessions, cookies, adapters, and plugins live here. | `gem "better_auth"` |
| [`better_auth-rails`](packages/better_auth-rails/) | Rails adapter with mounting helpers, ActiveRecord adapter, controller helpers, and generators. | `gem "better_auth-rails"` |
| [`better_auth-sinatra`](packages/better_auth-sinatra/) | Sinatra adapter with Rack mounting, request helpers, and SQL migration Rake tasks. | `gem "better_auth-sinatra"` |

## Quick Start

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

## Compatibility Status

Legend:

- [x] Supported: implemented in Ruby with local tests.
- [ ] Not supported: not implemented or intentionally outside the Ruby server scope.
- Partial: implemented for the main Ruby server path, with documented upstream parity gaps.

### Core

| Area | Status | Notes |
| --- | --- | --- |
| Auth factory and Rack handler | [x] Supported | `BetterAuth.auth(...)` returns a Rack-callable auth object with direct server API access. |
| Endpoint/router/API pipeline | Partial | Rack routing, direct API calls, hooks, redirects, cookies, origin checks, and rate limiting exist; some upstream edge-case matrices remain future work. |
| Email/password auth | Partial | Sign-up, sign-in, password reset, password verify, set/change password, and email verification exist; some upstream edge cases are still being hardened. |
| Social OAuth flow | Partial | `/sign-in/social`, `/callback/:providerId`, linking, unlinking, token refresh, and account info exist; upstream account-cookie and some linking-rule details are still future polish. |
| Sessions | Partial | Signed session cookies, session routes, revocation, cookie cache, secondary storage, and sensitive-route lookup exist; full upstream session/cache matrix is not complete. |
| Cookies | Partial | Prefixing, signing, chunking, deletion, cache cookies, and advanced attributes exist; filtering and some account-cookie parity gaps are documented. |
| CSRF/trusted origins | Partial | Origin checks and trusted origins exist; callback-bearing GET route parity is still being tightened. |
| Rate limiting | Partial | Memory/custom/secondary-storage style rate limiting exists; full database-backed upstream matrix remains future work. |
| Hooks and database hooks | [x] Supported | Before/after endpoint hooks, plugin hooks, and adapter database hooks are implemented. |
| Plugin system | [x] Supported | Ruby plugins can add endpoints, schema, hooks, middleware, rate limits, error codes, and option defaults. |
| Database schema | [x] Supported | Core schema plus plugin schema merge, logical Better Auth field names, and SQL/Rails migration generation exist. |
| Memory adapter | [x] Supported | Default development/test adapter. |
| PostgreSQL adapter | Partial | Direct SQL adapter and DDL generation exist; full upstream adapter contract coverage is still expanding. |
| MySQL adapter | Partial | Direct SQL adapter and DDL generation exist; full upstream adapter contract coverage is still expanding. |
| Rails ActiveRecord adapter | Partial | ActiveRecord persistence, migrations, mounting, helpers, and generators exist; full adapter contract parity is still expanding. |
| Sinatra adapter | Partial | Rack mounting, helpers, SQL migration Rake tasks, and docs exist. ActiveRecord-backed Sinatra migrations are not supported yet. |
| Secondary storage | Partial | Session and verification-style storage behavior exists; full edge-case parity remains future work. |
| Experimental joins | Partial | `experimental: { joins: true }` is accepted with adapter fallback behavior; the exhaustive join matrix is not complete. |
| OpenAPI generation | Partial | Practical OpenAPI 3.1 route/model generation exists; upstream Zod snapshot parity is future work. |

### Social Providers

Upstream Better Auth exposes many provider factories. The Ruby port currently ships the most common factories and the generic OAuth plugin can cover custom providers.

| Provider | Status | Notes |
| --- | --- | --- |
| Apple | Partial | Factory and OAuth profile mapping exist. |
| Discord | Partial | Factory and OAuth profile mapping exist. |
| GitHub | Partial | Factory, token exchange, and email/profile lookup exist. |
| GitLab | Partial | Factory and OAuth profile mapping exist. |
| Google | Partial | Factory and OpenID profile mapping exist. |
| Microsoft Entra ID | Partial | Factory and OpenID profile mapping exist. |
| Atlassian, Cognito, Dropbox, Facebook, Figma, Hugging Face, Kakao, Kick, Line, Linear, LinkedIn, Naver, Notion, Paybin, PayPal, Polar, Reddit, Roblox, Salesforce, Slack, Spotify, TikTok, Twitch, Twitter/X, Vercel, VK, Zoom | [ ] Not supported as built-in factories | Use `BetterAuth::Plugins.generic_oauth` or add a Ruby provider factory. |

### Plugins

| Plugin | Status | Notes |
| --- | --- | --- |
| Access control | [x] Supported | Runtime roles, statements, permissions, resource/action connectors, and upstream access checks are implemented; TypeScript inference is outside Ruby scope. |
| Additional fields | [x] Supported | Schema extension and route integration exist. |
| Admin | [x] Supported | Ruby server parity covers user management, list/search/filter/sort/count, role validation, bans including social callback rejection and expiry cleanup, impersonation/admin-session restoration, session administration, password setting, destructive endpoints, and permission checks. |
| Anonymous | [x] Supported | Anonymous sign-in/delete, generator fallbacks, repeat-session rejection, and email/social link cleanup are implemented. |
| API key | [x] Supported | Creation, verification, hashing, expiration bounds, usage/refill/rate limits, metadata migration, permissions, storage modes, deferred updates, and API-key sessions are implemented. |
| Bearer | [x] Supported | Bearer session resolution, signed-token exposure, unsigned-token fallback, signature requirement, list-session auth, and valid-cookie fallback are implemented. |
| Captcha | [x] Supported | reCAPTCHA, hCaptcha, Turnstile, CaptchaFox, protected endpoint checks, provider payloads, score checks, and failure responses are implemented. |
| Custom session | [x] Supported | Custom `/get-session` shaping, unauthenticated nil responses, Set-Cookie preservation, and optional multi-session list mutation are implemented. |
| Device authorization | [x] Supported | Device/user code issuance, option validation, client validation, OAuth error responses, polling/slow-down, approval/denial, token exchange hooks, expiry, and verification URI behavior are implemented. |
| Email OTP | [x] Supported | Send/check/verify/sign-in/password-reset flows, attempts, latest OTP, no-enumeration sends, override hooks, token storage modes, and plugin rate limits are implemented. Client aliases are outside Ruby server scope. |
| Generic OAuth | [x] Supported | Custom OAuth sign-in/callback/link flows, DB and cookie state strategies with mismatch cleanup, dynamic authorization params, response mode, issuer checks, sign-up controls, custom token/user-info callables, standard HTTP token/userinfo exchange, provider helper factories, account-info/refresh integration, encrypted OAuth tokens, account cookies, and account linking are implemented. |
| Have I Been Pwned | [x] Supported | SHA-1 k-anonymity range lookup, default password-route protection, custom paths/messages, and injectable lookup tests are implemented. |
| JWT/JWKS | [x] Supported | EdDSA default signing, RS256/PS256/ES256/ES512 key generation, JWKS publication/custom path, key rotation/grace periods, `kid` selection, token expiry, remote JWKS verification, API-only sign/verify helpers, and `set-auth-jwt` are implemented. Symmetric client-secret algorithms such as HS256 are intentionally outside the JWKS server surface. |
| Last login method | [x] Supported | Successful email, SIWE, social OAuth, and generic OAuth logins update the readable cookie and optional `lastLoginMethod` user field; failed auth is suppressed and custom cookie names/prefixes/cross-origin attributes are covered. |
| Magic link | [x] Supported | Send/verify, redirects/errors, new-user signup, existing-user verification, latest-token verification, callback origin validation, and token storage modes are implemented. |
| MCP | [x] Supported | OAuth/protected-resource metadata, registration, authorization-code PKCE, token refresh, userinfo, JWKS publication, login-prompt cookie restoration, and helper challenge headers are implemented. |
| Multi-session | [x] Supported | Device sessions, active switching, same-user replacement, active-session authorization, revocation, sign-out cleanup, and invalid-token errors are implemented. |
| OAuth proxy | [x] Supported | Callback rewriting, same-origin unwrap, encrypted cross-origin cookie forwarding, timestamp/trusted-callback validation, malformed payload handling, stateless state-cookie package restoration, and DB-less provider callback flow are implemented. |
| OAuth provider | Partial | OAuth/OIDC metadata, client registration, consent, authorization-code/client-credentials tokens, introspection, and revocation exist; organization, logout, encrypted client-secret, and rate-limit matrices remain. |
| OIDC provider | Partial | Metadata, dynamic registration, consent-code flow, token, refresh token, userinfo, and logout exist. |
| One tap | [x] Supported | Google ID-token callback, account reuse/linking, trusted/verified account linking, disabled signup, client ID handling, invalid-token handling, and session cookies are implemented. Browser/FedCM helpers are outside Ruby server scope. |
| One-time token | [x] Supported | Generate/verify, single-use, expiration, expired-session rejection, cookie behavior, storage modes, server-only generation, and `set-ott` session headers are implemented. |
| OpenAPI | Partial | See core status above. |
| Organization | [x] Supported | Organization/member CRUD, invitations including multi-team acceptance, team flows, active org/team session fields, dynamic role CRUD safeguards, hooks, additional fields, permissions, and SQL/Rails plugin schema migrations are implemented. Browser client hooks and TypeScript inference are outside Ruby server scope. |
| Passkey | [x] Supported | WebAuthn registration/authentication, upstream option shapes, challenge expiration, allow/exclude credential transports, not-found delete behavior, management routes, session creation, and SQL/Rails schema output are implemented through the `webauthn` gem. Browser client package aliases are outside Ruby server scope. |
| Phone number | [x] Supported | OTP send/verify, sign-in/sign-up, phone updates, password reset safety, attempt limits, uniqueness, additional fields, custom validation, and custom OTP verification are implemented. |
| SIWE | Partial | Nonce, wallet sign-in, callback verification, ENS hook, and account/session creation exist; checksum casing remains a Ruby adaptation. |
| SSO | Partial | OIDC/SAML provider flows, domain verification, ACS/metadata, replay protection, and organization assignment exist; full SAML XML signature/encryption matrix remains future work. |
| SCIM | Partial | Tokens, metadata, user CRUD, common PATCH operations, filters, mappings, and Bearer middleware exist. |
| Stripe | [x] Supported | Injected-client checkout/portal flows, reference authorization, plan/seat/trial abuse protection, billing event webhooks, subscription state transitions, and organization subscriptions are covered. |
| Two-factor | [x] Supported | TOTP, OTP, backup codes, trusted devices, cookie max-age options, disable/recovery flows, `rememberMe: false` preservation, and post-login verification are implemented. |
| Username | [x] Supported | Username sign-up/sign-in, availability, normalization, display username, validation order, duplicate/update behavior, and leak-prevention behavior are implemented. |
| Expo server integration | [x] Supported | Authorization proxy cookies, optional OAuth state cookie, `expo-origin` override/preservation, disabled override, trusted `exp://`, wildcard trusted origins, and trusted deep-link cookie transfer are covered. Native Expo client storage/focus helpers are outside Ruby server scope. |

## Development

### Clone And Verify

```bash
git clone --recursive https://github.com/sebasxsala/better-auth.git
cd better-auth
make install
make ci
```

### One Package

```bash
cd packages/better_auth
bundle install
bundle exec rake test
```

## Documentation

The upstream docs app has been copied into [`docs/`](/Users/sebastiansala/projects/better-auth/docs/README.md) and is being adapted for Ruby/Rack/Rails. Pages that still contain upstream TypeScript examples include a warning callout at the top.

Ruby-first starter pages are available under `docs/content/docs/introduction.mdx`, `docs/content/docs/installation.mdx`, `docs/content/docs/basic-usage.mdx`, `docs/content/docs/concepts/database.mdx`, `docs/content/docs/integrations/rack.mdx`, `docs/content/docs/integrations/rails.mdx`, and `docs/content/docs/integrations/sinatra.mdx`.

## Monorepo Layout

```txt
better-auth/
├── upstream/                   # Submodule: upstream TypeScript Better Auth
├── docs/                       # Adapted upstream docs app
├── packages/
│   ├── better_auth/            # Core gem, Minitest
│   ├── better_auth-rails/      # Rails adapter, RSpec
│   └── better_auth-sinatra/    # Sinatra adapter, RSpec
├── .docs/
│   ├── features/               # Feature parity notes
│   └── plans/                  # Port implementation plans
├── Gemfile
├── Rakefile
└── Makefile
```

## Git Workflow

- `canary`: day-to-day development; open PRs here.
- `main`: stable line; releases and CI publish run from here when versions bump.
- `upstream/`: git submodule and reference only.

```bash
git checkout canary
git pull origin canary
git checkout -b feat/my-change
# ... commit ...
git push -u origin feat/my-change
# Open PR to canary
```

## Release

Releases are automated with GitHub Actions on push to `main` when `version.rb` changes. The Rails adapter is published as both `better_auth-rails` and `better_auth_rails` as a compatibility alias; the Sinatra adapter publishes as `better_auth-sinatra`.

Details: [RELEASING.md](RELEASING.md).

Dry-run locally:

```bash
make release-check
```

## Contributing

1. Fork the repo.
2. Branch from `canary`.
3. Read [AGENTS.md](AGENTS.md) and the relevant package instructions.
4. Run `make ci` before pushing.
5. Open a PR to `canary`.

## Security

Report vulnerabilities to security@openparcel.dev. See [SECURITY.md](SECURITY.md).

## License

[MIT License](LICENSE.md)
