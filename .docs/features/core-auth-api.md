# Feature: Core Auth API And Configuration

**Upstream Reference:** `upstream/packages/better-auth/src/auth/base.ts`, `upstream/packages/better-auth/src/context/create-context.ts`

## Summary

Phase 1 establishes the Ruby entrypoint and runtime object model: `BetterAuth.auth(options = {})`, `BetterAuth::Auth`, `BetterAuth::Configuration`, `BetterAuth::Context`, and base error-code merging.

## Upstream Implementation

Upstream `betterAuth(options)` returns an auth object with a request handler, server API, original options, async context, and merged error codes. Context creation normalizes `baseURL`/`basePath`, session defaults, DB-less stateless defaults, trusted origins, plugin options, rate-limit settings, and secret handling.

## Ruby Adaptation

Ruby exposes snake_case public names: `context` instead of `$context`, and `error_codes` instead of `$ERROR_CODES`. `BetterAuth::Auth#call(env)` is Rack-compatible and delegates to the router handler. Current core initialization wires the context, selected adapter, internal adapter, plugin registry, merged endpoints, direct `auth.api` facade, and Rack handler.

### Ruby-Specific Decisions

- Secret handling follows the plan's stricter rule: missing secrets fail outside test environments, while upstream falls back to `DEFAULT_SECRET` and only rejects that default in production.
- Public option keys are accepted as Ruby-style snake_case and normalized internally.
- Trusted-origin matching ports upstream exact-origin, wildcard, custom-scheme, relative-path, dynamic base URL, and trusted proxy behavior needed by current route/API tests.

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
