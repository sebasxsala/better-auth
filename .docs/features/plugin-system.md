# Plugin System

## Upstream References

- `upstream/packages/core/src/types/plugin.ts`
- `upstream/packages/better-auth/src/context/helpers.ts`
- `upstream/packages/better-auth/src/context/create-context.test.ts`
- `upstream/packages/better-auth/src/api/index.ts`
- `upstream/packages/better-auth/src/api/check-endpoint-conflicts.test.ts`
- `upstream/packages/better-auth/src/api/to-auth-endpoints.test.ts`
- `upstream/packages/core/src/db/get-tables.ts`

## Ruby Status

Phase 6 adds an explicit plugin contract in core:

- `BetterAuth::Plugin` wraps plugin definitions and normalizes upstream-style keys such as `onRequest`, `onResponse`, `rateLimit`, and `$ERROR_CODES` into Ruby snake-case readers.
- Hash-style plugin definitions remain supported for existing tests and future ergonomic configuration; `Configuration#plugins` now stores `BetterAuth::Plugin` instances that also respond to `[]`, `fetch`, and `dig`.
- `BetterAuth::PluginRegistry` initializes plugins in configured order, lets later plugins observe earlier context changes, merges plugin option defaults without overriding explicitly configured user options, merges plugin endpoints after base endpoints, and merges plugin error codes into the auth registry.
- `BetterAuth::PluginContext` applies plugin context mutations while protecting core-owned `options`, `adapter`, and `internal_adapter`.
- Plugin schemas continue to flow through `BetterAuth::Schema.auth_tables`, including field merges into base tables and new plugin-defined tables.
- Plugin middlewares, `on_request`, `on_response`, and endpoint `before`/`after` hooks run through the Rack router/API pipeline.

## Ruby Adaptations

- Upstream TypeScript plugins are object literals. Ruby accepts either hashes or `BetterAuth::Plugin.new(...)`; both become `BetterAuth::Plugin` instances internally.
- Upstream `defu(options, plugin_options)` treats plugin options as defaults. Ruby tracks the originally provided option paths so plugin defaults can override framework defaults but cannot override values explicitly set by the application.
- Upstream can attach arbitrary fields to the auth context. Ruby exposes plugin-added context fields via dynamic readers while keeping core adapter/configuration references protected from plugin context replacement.
- Plugin database hooks returned from `init` are retained on the plugin's own options and are picked up by `DatabaseHooks`; they are not folded into the top-level configured hooks to avoid duplicate execution.

## Covered Tests

- `packages/better_auth/test/better_auth/plugin_test.rb`
- Existing router/API/configuration/schema/internal-adapter tests covering plugin endpoints, hooks, conflict logging, schemas, request/response callbacks, and database hook plumbing.

## Deferred

- Concrete plugin implementations start in Phase 7.
- Plugin-specific adapter method overrides are represented on the contract but not yet consumed by the internal adapter until a concrete plugin needs them.
- Database-backed plugin rate-limit rules are still limited by the current rate-limit storage implementation.
