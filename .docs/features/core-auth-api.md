# Feature: Core Auth API And Configuration

**Upstream Reference:** `upstream/packages/better-auth/src/auth/base.ts`, `upstream/packages/better-auth/src/context/create-context.ts`

## Summary

Phase 1 establishes the Ruby entrypoint and runtime object model: `BetterAuth.auth(options = {})`, `BetterAuth::Auth`, `BetterAuth::Configuration`, `BetterAuth::Context`, and base error-code merging.

## Upstream Implementation

Upstream `betterAuth(options)` returns an auth object with a request handler, server API, original options, async context, and merged error codes. Context creation normalizes `baseURL`/`basePath`, session defaults, DB-less stateless defaults, trusted origins, plugin options, rate-limit settings, and secret handling.

## Ruby Adaptation

Ruby exposes snake_case public names: `context` instead of `$context`, and `error_codes` instead of `$ERROR_CODES`. `BetterAuth::Auth#call(env)` is Rack-compatible and delegates to the handler. The first handler is intentionally minimal until Phase 2 router work lands.

### Ruby-Specific Decisions

- Secret handling follows the plan's stricter rule: missing secrets fail outside test environments, while upstream falls back to `DEFAULT_SECRET` and only rejects that default in production.
- Public option keys are accepted as Ruby-style snake_case and normalized internally.
- Trusted-origin matching ports upstream exact-origin, wildcard, custom-scheme, and relative-path behavior needed by Phase 1 tests.

## Implementation

- `packages/better_auth/lib/better_auth.rb`
- `packages/better_auth/lib/better_auth/auth.rb`
- `packages/better_auth/lib/better_auth/configuration.rb`
- `packages/better_auth/lib/better_auth/context.rb`
- `packages/better_auth/lib/better_auth/error.rb`

## Testing

```bash
cd packages/better_auth
bundle exec rake test TEST=test/better_auth/auth_test.rb
bundle exec rake test TEST=test/better_auth/configuration_test.rb
bundle exec rake test
bundle exec standardrb
```

Key test files:

- `packages/better_auth/test/better_auth/auth_test.rb`
- `packages/better_auth/test/better_auth/configuration_test.rb`

