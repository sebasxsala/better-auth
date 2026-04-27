# Hanami Adapter

**Status:** Initial Hanami 2.3+ adapter implemented with Rack route mounting, Sequel persistence, ROM::SQL migrations, generated relations/repos, action helpers, and Rake/generator commands.

**Upstream Reference:** Better Auth upstream stays framework-agnostic at runtime. The Hanami adapter follows the Rails adapter pattern by mounting the core Rack auth object instead of reimplementing Better Auth routes as framework actions.

## Ruby/Hanami Adaptation

Hanami integration provides:

- `BetterAuth::Hanami.configure` and `BetterAuth::Hanami.auth` for building the core auth instance from Hanami configuration.
- `BetterAuth::Hanami::Routing#better_auth`, mounting all supported auth methods at `/api/auth` by default.
- `BetterAuth::Hanami::SequelAdapter`, backed by Hanami's ROM/Sequel gateway and returning Better Auth logical fields such as `emailVerified` and `userId`.
- `BetterAuth::Hanami::Migration.render`, emitting ROM::SQL migrations from `BetterAuth::Schema`, including plugin tables and fields.
- Generated `app/repo.rb`, `app/relations/*.rb`, and `app/repos/*_repo.rb` for core and configured plugin tables.
- Action helpers: `current_session(request)`, `current_user(request)`, `authenticated?(request)`, and `require_authentication(request, response)`.
- Rake/generator commands: `better_auth:init`, `better_auth:generate:migration`, and `better_auth:generate:relations`.

## Limitations

- Supports Hanami 2.3+ only. Hanami 2.3 is the first Hanami line that allows Rack 3, and Better Auth core depends on Rack 3.
- Hanami 1.x and Hanami 2.2/Rack 2 are out of scope.
- Command integration is intentionally Rake/generator based. The current public Hanami guides do not document a stable third-party CLI extension API for `hanami better_auth ...`.
- Production apps need a Hanami DB gateway or explicit adapter; memory mode is only suitable for development and tests.

## Verification

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-hanami
rbenv exec bundle exec rspec
rbenv exec bundle exec standardrb
```
