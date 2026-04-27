# Sinatra Adapter

**Status:** Initial Sinatra adapter implemented with Rack mounting, request helpers, SQL migration tasks, and docs.

**Upstream Reference:** Better Auth upstream exposes framework adapters as thin wrappers around the same auth handler. The Ruby Sinatra adapter follows the existing Rack/Rails shape by mounting the core `BetterAuth.auth` Rack object instead of reimplementing auth routes in Sinatra handlers.

## Ruby/Sinatra Adaptation

Sinatra integration provides:

- `BetterAuth::Sinatra.configure` and `BetterAuth::Sinatra.auth` for building the core auth instance from app configuration.
- `register BetterAuth::Sinatra` and `better_auth at: "/api/auth"` for mounting the core Rack auth app inside a Sinatra app.
- Helpers: `current_session`, `current_user`, `authenticated?`, and `require_authentication`.
- SQL migration Rake tasks: `better_auth:install`, `better_auth:generate:migration`, `better_auth:migrate`, and `better_auth:routes`.

The adapter keeps all auth behavior in `packages/better_auth`. Sinatra code only adapts configuration, mounting, helper ergonomics, and SQL migration workflow.

## Database Notes

Sinatra has no built-in database adapter or universal migration command equivalent to `bin/rails db:migrate`. The first Better Auth Sinatra integration therefore uses the existing core SQL adapters and SQL schema renderer. Generated migrations live under `db/better_auth/migrate` and are tracked through a `better_auth_schema_migrations` table.

ActiveRecord-backed Sinatra migrations are not supported yet. This is intentional for v1 because ActiveRecord is not a Sinatra default and adding it as a runtime dependency would overfit one Sinatra stack. A future adapter can add optional `sinatra-activerecord` integration.

Unsupported migration targets:

- memory adapter;
- MongoDB adapter;
- custom adapters that do not expose `connection` and `dialect`;
- ActiveRecord-backed Sinatra apps until optional support is added.

## Verification

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-sinatra
rbenv exec bundle exec rspec
RUBOCOP_CACHE_ROOT=/private/var/folders/7x/jrsz946d2w73n42fb1_ff5000000gn/T/rubocop_cache_sinatra rbenv exec bundle exec standardrb
```
