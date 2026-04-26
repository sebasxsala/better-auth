# Rails Adapter

**Status:** Phase 5.5 complete for the initial Rails adapter surface.

**Upstream Reference:** Better Auth upstream is framework-agnostic at the route/runtime layer. The Rails adapter keeps that shape by mounting the core Rack auth object instead of reimplementing auth routes in controllers.

## Ruby/Rails Adaptation

Rails integration now provides:

- `BetterAuth::Rails.configure` and `BetterAuth::Rails.auth` for building the core auth instance from Rails configuration.
- `BetterAuth::Rails::ActiveRecordAdapter`, an ActiveRecord-backed adapter that maps logical Better Auth fields like `emailVerified` and `userId` to Rails/PostgreSQL-friendly columns like `email_verified` and `user_id`.
- `better_auth` route helper for `config/routes.rb`, mounting a single Rack app at `/api/auth` by default.
- Controller helpers: `current_session`, `current_user`, and `authenticated?`.
- Generators: `bin/rails generate better_auth:install` and `bin/rails generate better_auth:migration`.
- Rails task aliases: `bin/rails better_auth:init` and `bin/rails better_auth:generate:migration`.

The install generator creates `config/initializers/better_auth.rb` and the base schema migration. It skips an existing initializer or existing Better Auth migration rather than overwriting app code. The migration is rendered from `BetterAuth::Schema`, so plugin schema can be layered into the same path later.

## Database Notes

The initial migration follows the direct SQL decisions from the core gem: plural `snake_case` tables, `snake_case` columns, unique indexes, explicit indexes for foreign keys, and `ON DELETE CASCADE` for user-owned rows.

ActiveRecord is declared as a runtime dependency of `better_auth-rails`. The adapter has RSpec coverage with fakes for contract mapping and transaction behavior, plus a PostgreSQL integration spec that:

- renders the Rails migration from `BetterAuth::Schema`;
- runs that generated migration against the Docker PostgreSQL service;
- verifies the `users` table, unique email index, primary keys, and foreign keys are created;
- creates and reads a user through `BetterAuth::Rails::ActiveRecordAdapter`;
- reads the same user through the core `BetterAuth::Adapters::Postgres` SQL adapter.
- runs Rack signup, signin, and get-session base routes against ActiveRecord persistence, including rebuilding the auth instance between signup and signin.

MySQL real-database Rails coverage and the broader Phase 13 Rails hardening matrix remain pending.

## Verification

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-rails
rbenv exec bundle exec rspec
RUBOCOP_CACHE_ROOT=/private/var/folders/7x/jrsz946d2w73n42fb1_ff5000000gn/T/rubocop_cache_rails rbenv exec bundle exec standardrb
```
