# Feature: Database Schema, Adapters, And Internal Adapter

**Upstream Reference:** `upstream/packages/core/src/db/get-tables.ts`, `upstream/packages/better-auth/src/adapters/memory-adapter/memory-adapter.ts`, `upstream/packages/better-auth/src/db/internal-adapter.ts`, `upstream/packages/better-auth/src/db/with-hooks.ts`, `upstream/packages/better-auth/src/db/secondary-storage.test.ts`

## Summary

Phase 3 adds the persistence layer used by later auth routes and plugins: the core schema map, a framework-agnostic adapter contract, the default memory adapter, database hooks, and an internal adapter for user/account/session/verification workflows. Phase 4.5 starts real SQL support with direct PostgreSQL/MySQL/SQLite/MSSQL DDL generation and a shared SQL adapter, plus a standalone MongoDB adapter, without introducing Rails or ActiveRecord into the core gem.

## Upstream Implementation

Upstream builds auth tables from core schema, user options, plugin schemas, and rate-limit settings. Adapter factories translate Better Auth model and field names into storage names, apply defaults, handle joins, and support CRUD operations. The internal adapter wraps those CRUD operations with database hooks and coordinates secondary-storage sessions through `active-sessions-*` lists plus per-token session payloads.

## Ruby Adaptation

Ruby keeps upstream logical and wire field names such as `emailVerified`, `userId`, `expiresAt`, `providerId`, `accountId`, and `accessToken` even though method names stay snake_case. `BetterAuth::Schema` produces PostgreSQL-friendly physical table/column metadata, `BetterAuth::Adapters::Memory` stores records in process memory, and `BetterAuth::Adapters::InternalAdapter` provides the higher-level persistence API that future route phases will call.

### Design Decisions

- The core gem remains Rails-free. Direct SQL adapters live in core, but Rails/ActiveRecord integration remains a separate adapter layer.
- Schema metadata separates Better Auth logical names from physical SQL names. Logical keys stay upstream-compatible (`user`, `session`, `emailVerified`, `userId`), while default physical names are `snake_case` and avoid quoted mixed-case identifiers.
- Core physical table defaults use PostgreSQL/Rails-friendly plural names: `users`, `sessions`, `accounts`, `verifications`, and `rate_limits`. Apps that need exact upstream JavaScript table names can still override `model_name`.
- Default physical column names are `snake_case`: `email_verified`, `created_at`, `updated_at`, `user_id`, `ip_address`, `user_agent`, `access_token`, and similar plugin fields such as `active_organization_id`.
- PostgreSQL indexing metadata is carried forward for migration work: unique fields such as `email` and session `token` remain marked unique, and FK fields such as `user_id` remain marked indexed because PostgreSQL does not auto-index foreign keys.
- DB-less auth now defaults to the memory adapter while keeping the Phase 1 stateless-session option defaults.
- Secondary storage omits the `session` table unless `session: { store_session_in_database: true }` is set, matching upstream.
- Redis secondary storage lives in the external `better_auth-redis-storage` package so core does not install Redis client dependencies for apps that do not use it.
- Database hooks use Ruby callables and may mutate data by returning `{ data: ... }` or cancel by returning `false`.
- The memory adapter implements Better Auth-specific where operators, basic joins for `session -> user`, `account -> user`, and `user -> account`, sorting, pagination, counts, and rollbackable in-memory transactions.
- The direct SQL layer generates PostgreSQL, MySQL, SQLite, and MSSQL schema DDL from the same `BetterAuth::Schema` metadata. PostgreSQL uses `text`, `boolean`, `timestamptz`, `bigint`, FK constraints, and explicit FK indexes. MySQL uses InnoDB, `utf8mb4`, `varchar(191)` for indexed strings, `text`, `tinyint(1)`, `datetime(6)`, FK constraints, and explicit FK indexes. SQLite uses `text`, `integer`, `date`, FK constraints, and explicit FK indexes. MSSQL uses `varchar(255)`/`varchar(8000)`, `smallint`, `datetime2(3)`, FK constraints, and explicit FK indexes.
- `BetterAuth::Adapters::SQL` implements parameterized CRUD, count, transactions, logical-to-physical field mapping, current internal-adapter joins for SQL-backed storage, and collection aggregation for `user -> account`. `BetterAuth::Adapters::Postgres`, `BetterAuth::Adapters::MySQL`, `BetterAuth::Adapters::SQLite`, and `BetterAuth::Adapters::MSSQL` are thin wrappers that require `pg`, `mysql2`, `sqlite3`, or `sequel`/`tiny_tds` only when instantiated without an injected connection. MSSQL uses Sequel internally for safer parameter binding; this is not exposed as a public Sequel adapter.
- `BetterAuth::Adapters::MongoDB` is a standalone adapter, not a SQL wrapper. It stores documents in upstream-style singular collections by default, maps logical `id` to Mongo `_id`, maps configured field names such as `emailVerified` to storage names such as `email_verified`, converts ObjectId-compatible ids when the Mongo driver is available, supports the shared CRUD/where/sort/join contract, and can wrap operations in Mongo client sessions when transactions are enabled.
- `BetterAuth::Rails::ActiveRecordAdapter` defines dynamic ActiveRecord associations for supported joins and uses native eager loading for `session -> user`, `account -> user`, and `user -> account`, avoiding per-record manual lookup while preserving the same logical result shape.
- PostgreSQL output normalization now coerces `pg` string values such as `"f"`/`"t"` and timestamp strings back into Ruby booleans and `Time` values before returning logical Better Auth hashes.

### Experimental Joins

Ruby accepts the upstream public option `experimental: { joins: true }`. Joins are treated as an optimization, not a behavior switch: when enabled and supported by the adapter, the internal adapter requests native joins; when disabled or unsupported, it performs separate adapter reads and combines the same logical response. Core SQL adapters use SQL joins for supported relationships, and the Rails ActiveRecord adapter now uses native eager loading for those supported relationships. This keeps the option safe for production Ruby apps while preserving upstream's documented configuration shape.

## Configuration Examples

Framework-agnostic Rack apps can instantiate auth directly:

```ruby
auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: BetterAuth::Adapters::Postgres.new(url: ENV.fetch("DATABASE_URL"))
)
```

```ruby
auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: BetterAuth::Adapters::MySQL.new(url: ENV.fetch("DATABASE_URL"))
)
```

```ruby
auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: BetterAuth::Adapters::SQLite.new(path: "storage/auth.sqlite3")
)
```

```ruby
auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: BetterAuth::Adapters::MongoDB.new(database: mongo_client.database, client: mongo_client)
)
```

```ruby
auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: BetterAuth::Adapters::MSSQL.new(url: ENV.fetch("DATABASE_URL"))
)
```

Rails should later put equivalent configuration in `config/initializers/better_auth.rb`, but Rails should still mount the core Rack app rather than reimplement routes in controllers.

## Implementation

- `packages/better_auth/lib/better_auth/schema.rb`
- `packages/better_auth/lib/better_auth/adapters/base.rb`
- `packages/better_auth/lib/better_auth/adapters/memory.rb`
- `packages/better_auth/lib/better_auth/adapters/sql.rb`
- `packages/better_auth/lib/better_auth/adapters/postgres.rb`
- `packages/better_auth/lib/better_auth/adapters/mysql.rb`
- `packages/better_auth/lib/better_auth/adapters/sqlite.rb`
- `packages/better_auth/lib/better_auth/adapters/mongodb.rb`
- `packages/better_auth/lib/better_auth/adapters/mssql.rb`
- `packages/better_auth/lib/better_auth/database_hooks.rb`
- `packages/better_auth/lib/better_auth/adapters/internal_adapter.rb`
- `packages/better_auth/lib/better_auth/schema/sql.rb`
- `packages/better_auth/lib/better_auth/auth.rb`
- `packages/better_auth/lib/better_auth/context.rb`
- `packages/better_auth/lib/better_auth/configuration.rb`
- `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb`

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/schema_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/schema/sql_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/adapters/memory_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/adapters/sql_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/adapters/postgres_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/adapters/mysql_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/adapters/sqlite_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/adapters/mongodb_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/adapters/mssql_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/adapters/internal_adapter_test.rb
```

Key test files:

- `packages/better_auth/test/better_auth/schema_test.rb`
- `packages/better_auth/test/better_auth/schema/sql_test.rb`
- `packages/better_auth/test/better_auth/adapters/memory_test.rb`
- `packages/better_auth/test/better_auth/adapters/sql_test.rb`
- `packages/better_auth/test/better_auth/adapters/postgres_test.rb`
- `packages/better_auth/test/better_auth/adapters/mysql_test.rb`
- `packages/better_auth/test/better_auth/adapters/sqlite_test.rb`
- `packages/better_auth/test/better_auth/adapters/mongodb_test.rb`
- `packages/better_auth/test/better_auth/adapters/mssql_test.rb`
- `packages/better_auth/test/better_auth/adapters/internal_adapter_test.rb`

## Notes

PostgreSQL and MySQL direct SQL support are exercised against Docker services in CI. SQLite, MongoDB, and MSSQL now have matching adapter tests with real-service coverage that skips cleanly when local driver gems or services are unavailable. The adapter tests cover both raw CRUD and BetterAuth route flows: sign-up creates user/account/session records verified through direct storage reads, and `get_session` returns the authoritative user/session after a direct storage update. ActiveRecord lives in `better_auth-rails` so Rails remains a thin integration layer over the same core route and adapter contracts.
