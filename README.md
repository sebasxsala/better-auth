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
| Access control | Partial | Runtime roles, statements, permissions, and role inference behavior are implemented. |
| Additional fields | [x] Supported | Schema extension and route integration exist. |
| Admin | Partial | User management, roles, bans, impersonation, and session administration exist; broader upstream matrices remain future polish. |
| Anonymous | Partial | Anonymous sign-in/delete and link cleanup exist; some upstream edge cases remain future polish. |
| API key | Partial | Key creation, verification, hashing, expiration, usage limits, metadata, storage modes, and API-key sessions exist. |
| Bearer | Partial | Bearer session resolution exists; some signature/header edge cases remain future polish. |
| Captcha | Partial | reCAPTCHA, hCaptcha, Turnstile, and CaptchaFox provider hooks exist. |
| Custom session | Partial | Custom session shaping exists; cookie/header preservation needs broader parity coverage. |
| Device authorization | Partial | Device/user code, polling, approval, denial, expiry, slow-down, and verification URI behavior exist. |
| Email OTP | Partial | Send/check/verify/sign-in/password-reset flows, attempts, and token storage modes exist. |
| Generic OAuth | Partial | Custom OAuth sign-in/callback/link flows exist; exhaustive provider/server matrix remains future polish. |
| Have I Been Pwned | Partial | SHA-1 k-anonymity range lookup with injectable tests exists. |
| JWT/JWKS | Partial | RS256 JWT issuance and JWKS publication exist; rotation and broader JOSE matrix remain future work. |
| Last login method | Partial | Cookie and optional user persistence exist. |
| Magic link | Partial | Send/verify, redirects, new-user signup, existing-user verification, and token storage modes exist. |
| MCP | Partial | OAuth metadata, protected resource metadata, registration, token, refresh, userinfo, and helper behavior exist. |
| Multi-session | Partial | Device sessions, active switching, and revocation exist; some auth/max-session edge cases remain future polish. |
| OAuth proxy | Partial | Callback rewriting, encrypted cookie forwarding, timestamp validation, and trusted callback validation exist. |
| OIDC provider | Partial | Metadata, dynamic registration, consent-code flow, token, refresh token, userinfo, and logout exist. |
| One tap | Partial | Google ID-token callback, account reuse/linking, disable signup, and session cookies exist; browser/FedCM helpers are outside core Ruby. |
| One-time token | Partial | Generate/verify, single-use, expiration, cookie behavior, and storage modes exist. |
| OpenAPI | Partial | See core status above. |
| Organization | Partial | Organizations, members, invitations, teams, active org/team, dynamic roles, hooks, and permissions exist. |
| Passkey | Partial | WebAuthn registration/authentication, challenge cookies, management routes, and session creation exist through the `webauthn` gem. |
| Phone number | Partial | OTP, sign-in/sign-up, phone updates, password reset, attempt limits, and custom validation exist. |
| SIWE | Partial | Nonce, wallet sign-in, callback verification, ENS hook, and account/session creation exist; checksum casing remains a Ruby adaptation. |
| SSO | Partial | OIDC/SAML provider flows, domain verification, ACS/metadata, replay protection, and organization assignment exist; full SAML XML signature/encryption matrix remains future work. |
| SCIM | Partial | Tokens, metadata, user CRUD, common PATCH operations, filters, mappings, and Bearer middleware exist. |
| Stripe | Partial | Injected-client checkout, billing portal, subscription persistence, webhooks, cancellation, restore, and organization mode exist. |
| Two-factor | Partial | TOTP, OTP, backup codes, trusted devices, enable/disable, and post-login verification exist. |
| Username | Partial | Username sign-up/sign-in, availability, normalization, display username, and leak-prevention behavior exist. |
| Expo/mobile server integration | Partial | Origin override, deep-link redirect cookie transfer, and authorization proxy exist; native client storage/focus helpers are outside Ruby server scope. |

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

Report vulnerabilities to security@better-auth.com. See [SECURITY.md](SECURITY.md).

## License

[MIT License](LICENSE.md)
