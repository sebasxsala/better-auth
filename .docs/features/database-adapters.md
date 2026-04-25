# Feature: Database Schema, Adapters, And Internal Adapter

**Upstream Reference:** `upstream/packages/core/src/db/get-tables.ts`, `upstream/packages/better-auth/src/adapters/memory-adapter/memory-adapter.ts`, `upstream/packages/better-auth/src/db/internal-adapter.ts`, `upstream/packages/better-auth/src/db/with-hooks.ts`, `upstream/packages/better-auth/src/db/secondary-storage.test.ts`

## Summary

Phase 3 adds the persistence layer used by later auth routes and plugins: the core schema map, a framework-agnostic adapter contract, the default memory adapter, database hooks, and an internal adapter for user/account/session/verification workflows.

## Upstream Implementation

Upstream builds auth tables from core schema, user options, plugin schemas, and rate-limit settings. Adapter factories translate Better Auth model and field names into storage names, apply defaults, handle joins, and support CRUD operations. The internal adapter wraps those CRUD operations with database hooks and coordinates secondary-storage sessions through `active-sessions-*` lists plus per-token session payloads.

## Ruby Adaptation

Ruby keeps upstream logical and wire field names such as `emailVerified`, `userId`, `expiresAt`, `providerId`, `accountId`, and `accessToken` even though method names stay snake_case. `BetterAuth::Schema` produces PostgreSQL-friendly physical table/column metadata, `BetterAuth::Adapters::Memory` stores records in process memory, and `BetterAuth::Adapters::InternalAdapter` provides the higher-level persistence API that future route phases will call.

### Design Decisions

- The core gem remains Rails-free and does not add a SQL dependency in Phase 3.
- Schema metadata separates Better Auth logical names from physical SQL names. Logical keys stay upstream-compatible (`user`, `session`, `emailVerified`, `userId`), while default physical names are `snake_case` and avoid quoted mixed-case identifiers.
- Core physical table defaults use PostgreSQL/Rails-friendly plural names: `users`, `sessions`, `accounts`, `verifications`, and `rate_limits`. Apps that need exact upstream JavaScript table names can still override `model_name`.
- Default physical column names are `snake_case`: `email_verified`, `created_at`, `updated_at`, `user_id`, `ip_address`, `user_agent`, `access_token`, and similar plugin fields such as `active_organization_id`.
- PostgreSQL indexing metadata is carried forward for migration work: unique fields such as `email` and session `token` remain marked unique, and FK fields such as `user_id` remain marked indexed because PostgreSQL does not auto-index foreign keys.
- DB-less auth now defaults to the memory adapter while keeping the Phase 1 stateless-session option defaults.
- Secondary storage omits the `session` table unless `session: { store_session_in_database: true }` is set, matching upstream.
- Database hooks use Ruby callables and may mutate data by returning `{ data: ... }` or cancel by returning `false`.
- The memory adapter implements Better Auth-specific where operators, basic joins for `session -> user`, `account -> user`, and `user -> account`, sorting, pagination, counts, and rollbackable in-memory transactions.

## Implementation

- `packages/better_auth/lib/better_auth/schema.rb`
- `packages/better_auth/lib/better_auth/adapters/base.rb`
- `packages/better_auth/lib/better_auth/adapters/memory.rb`
- `packages/better_auth/lib/better_auth/database_hooks.rb`
- `packages/better_auth/lib/better_auth/adapters/internal_adapter.rb`
- `packages/better_auth/lib/better_auth/auth.rb`
- `packages/better_auth/lib/better_auth/context.rb`
- `packages/better_auth/lib/better_auth/configuration.rb`

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/schema_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/adapters/memory_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/adapters/internal_adapter_test.rb
```

Key test files:

- `packages/better_auth/test/better_auth/schema_test.rb`
- `packages/better_auth/test/better_auth/adapters/memory_test.rb`
- `packages/better_auth/test/better_auth/adapters/internal_adapter_test.rb`

## Notes

No direct SQL database adapter is implemented in Phase 3. The current database-facing behavior is adapter-contract and memory-adapter parity; real SQL/ActiveRecord integration remains in later adapter/Rails phases.
