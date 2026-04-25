# Feature: Endpoint, API, Router, Middleware, Hooks

**Upstream Reference:** `upstream/packages/better-auth/src/api/index.ts`, `upstream/packages/better-auth/src/api/to-auth-endpoints.ts`, `upstream/packages/better-auth/src/api/middlewares/origin-check.ts`, `upstream/packages/better-auth/src/api/check-endpoint-conflicts.test.ts`

## Summary

Phase 2 adds the shared request execution pipeline for the Ruby core gem: endpoint objects, direct server API calls, Rack routing, origin/CSRF checks, plugin request/response hooks, basic rate limiting, and endpoint conflict logging.

## Upstream Implementation

Upstream wraps Better Auth endpoints with `toAuthEndpoints` for direct server calls and `createRouter` for HTTP requests. Direct `auth.api` calls run endpoint before/after hooks but intentionally skip router middleware such as origin checks, plugin `onRequest`, and rate limiting. HTTP requests run router middleware in order: origin check, plugin middleware, disabled path handling, plugin `onRequest`, rate limit, endpoint, and plugin `onResponse`.

## Ruby Adaptation

Ruby exposes `BetterAuth::Endpoint`, `BetterAuth::API`, and `BetterAuth::Router`. Endpoints use Rack-compatible response arrays for `as_response` and HTTP handling. Hooks use Ruby callables and hashes while preserving upstream semantics: user hooks run before plugin hooks, before hooks can merge context or short-circuit, after hooks can replace responses, and `Set-Cookie` headers append instead of overwrite.

### Design Decisions

- Phase 2 tests use synthetic endpoints for pipeline behavior because full email/session/OAuth route semantics are scheduled for later phases.
- Generic cookie/header aggregation is implemented now; Better Auth cookie names, signed session cookies, chunking, and session cache behavior remain Phase 4 work.
- Generic header setting rejects CR/LF in names and values to avoid header injection while cookie/session-specific encoding remains Phase 4 work.
- Rate limiting defaults to an in-memory store for Phase 2, but it now accepts `rate_limit: { custom_storage: ... }` and `storage: "secondary-storage"` so apps can avoid process-local counters before adapter-backed rate limits land. The limiter also mirrors upstream special auth-route defaults, custom path rules, disabled custom rules, upstream-style retry headers, IP tracking disablement, configurable IP headers, and IPv6 subnet normalization.
- Request-time base URL inference and trusted proxy header handling live on `BetterAuth::Context` so Rack requests without configured `base_url` can still populate trusted origins.
- Endpoint schema fields are enforced through a small adapter contract instead of a hard validator dependency: schemas may respond to `parse`, be callable, or return dry-style objects that answer `success?`/`to_h`.
- Trusted proxy headers follow the upstream validation shape: only `http`/`https` protocols are accepted, suspicious host characters are rejected, and invalid forwarded values fall back to the actual Rack request origin.
- Router body parsing enforces upstream's JSON-by-default media policy. Form submissions are accepted only when an endpoint explicitly declares `metadata: { allowed_media_types: [...] }`, which keeps future state-changing routes from accidentally accepting broad form posts.

### Dependency Decision

Phase 2 intentionally does not add `rack-attack`, `rack-protection`, `dry-validation`, `addressable`, or `public_suffix` as runtime dependencies. The core gem instructions currently limit runtime dependencies to Rack/JSON/JWT/BCrypt, and upstream has Better Auth-specific behavior for endpoint hooks, origin callbacks, Fetch Metadata CSRF checks, plugin rate-limit rules, and schema error shapes. Adding generic Rack middleware here would make the Ruby port less flexible and could drift from upstream semantics.

The current design keeps extension points open:

- Rate limiting can use custom or secondary storage now; database-backed storage belongs with Phase 3 adapters.
- Endpoint schemas can wrap third-party validators later without exposing those gems as required dependencies.
- URL/origin parsing remains local and test-driven against upstream cases; `addressable`/`public_suffix` can still be evaluated if later wildcard or domain behavior requires it.

## Implementation

- `packages/better_auth/lib/better_auth/api_error.rb`
- `packages/better_auth/lib/better_auth/endpoint.rb`
- `packages/better_auth/lib/better_auth/api.rb`
- `packages/better_auth/lib/better_auth/router.rb`
- `packages/better_auth/lib/better_auth/middleware/origin_check.rb`
- `packages/better_auth/lib/better_auth/rate_limiter.rb`

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/endpoint_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/router_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/api_test.rb
rbenv exec bundle exec rake test
RUBOCOP_CACHE_ROOT=/var/folders/7x/jrsz946d2w73n42fb1_ff5000000gn/T/rubocop_cache rbenv exec bundle exec standardrb
```

Key test files:

- `packages/better_auth/test/better_auth/endpoint_test.rb`
- `packages/better_auth/test/better_auth/api_test.rb`
- `packages/better_auth/test/better_auth/router_test.rb`

## Notes

Direct `auth.api` calls intentionally do not pass through all Rack router middleware, matching upstream. Use Rack requests against `auth.call(env)` or `auth.handler.call(env)` when testing origin checks, plugin `on_request`, plugin `on_response`, and rate limiting.
