# Core API Router Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port Ruby-applicable upstream API/router/rate-limit/origin-check tests into `packages/better_auth`.

**Architecture:** Keep endpoint conversion, direct API calls, Rack routing, origin checks, endpoint conflicts, and rate limiting inside the existing `API`, `Endpoint`, `Router`, `Middleware::OriginCheck`, and `RateLimiter` boundaries.

**Tech Stack:** Ruby 3.2+, Minitest, Rack, existing memory adapter and secondary storage test helpers.

---

## Audit Summary

Upstream files:

- `api/to-auth-endpoints.test.ts` — 51 titles
- `api/index.test.ts` — 7 titles
- `api/check-endpoint-conflicts.test.ts` — 13 titles
- `api/middlewares/origin-check.test.ts` — 31 titles
- `api/rate-limiter/rate-limiter.test.ts` — 20 titles

Existing Ruby targets:

- `packages/better_auth/test/better_auth/api_test.rb` — 7 tests
- `packages/better_auth/test/better_auth/endpoint_test.rb` — 7 tests
- `packages/better_auth/test/better_auth/router_test.rb` — 32 tests
- `packages/better_auth/test/better_auth/request_ip_test.rb` — 5 tests

Differences found:

- Endpoint hook mutation, array replacement, and schema parsing now cover query/body/params/headers/context/path/request Ruby equivalents. Ruby added `params_schema` support to match upstream parser coverage.
- Direct API and Rack behavior now cover context reset/preparation, trailing slash normalization for GET and POST, plugin request ordering/replacement, early responses, and response wrapping.
- Conflict detection now covers identical paths, wildcard methods, method arrays, duplicate endpoints inside one plugin, plugin IDs, and logger message shape.
- Origin check now covers malformed/missing origins, safe methods, callback variants, relative path policy, fetch metadata modes, CSRF/origin disabling split, and path-scoped origin skipping.
- Rate limiting now covers retry headers, path keys with query ignored, special and non-special rules, storage reset timing, secondary storage TTLs, custom storage shape, disabled rules, missing-IP fallback warning, and IP normalization boundaries.

## Tasks

### Task 1: Endpoint Conversion And Hook Mutation

**Files:**
- Modify: `packages/better_auth/test/better_auth/endpoint_test.rb`
- Modify: `packages/better_auth/test/better_auth/api_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/api.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/endpoint.rb`

- [x] Add tests translating upstream setter cases for query, body, params, headers, path, request, context, and returned response.
- [x] Add tests for hook array replacement vs deep hash merge using existing `API#call_endpoint`.
- [x] Add tests for endpoint schemas parsing headers/query/body/params before handlers.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/endpoint_test.rb test/better_auth/api_test.rb`.

### Task 2: Direct API And Router Request Chain

**Files:**
- Modify: `packages/better_auth/test/better_auth/api_test.rb`
- Modify: `packages/better_auth/test/better_auth/router_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/api.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/router.rb`

- [x] Add tests for context preparation before direct and Rack endpoint execution.
- [x] Add tests for plugin `on_request` ordering, request replacement, response short-circuiting, and `on_response` around early responses.
- [x] Add tests for default trailing slash 404 and configured trailing slash normalization.
- [x] Add tests for direct API returning Rack response triples, headers, status, and API errors.
- [x] Run focused API/router tests.

### Task 3: Endpoint Conflict Matrix

**Files:**
- Modify: `packages/better_auth/test/better_auth/router_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/router.rb`

- [x] Add tests for no conflicts, same path with different methods, same path with same method, wildcard method conflicts, method array conflicts, and duplicate endpoints inside one plugin.
- [x] Assert logger receives one actionable conflict message with path, methods, and plugin IDs.
- [x] Assert auth construction does not raise when conflicts are logged.
- [x] Run router tests.

### Task 4: Origin And CSRF Checks

**Files:**
- Modify: `packages/better_auth/test/better_auth/router_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/middleware/origin_check.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/configuration.rb`

- [x] Add tests for trusted/untrusted origin headers with and without cookies.
- [x] Add tests for callback URL and redirect target validation using trusted origins and relative path policy.
- [x] Add tests for fetch metadata headers: same-origin, same-site, cross-site, navigate, no-cors, and missing metadata.
- [x] Add tests for `disableOriginCheck`, `disableCSRFCheck`, test environment defaults, and route metadata overrides.
- [x] Run router tests.

### Task 5: Rate Limiter Matrix

**Files:**
- Modify: `packages/better_auth/test/better_auth/router_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/rate_limiter.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/request_ip.rb`

- [x] Add tests for sign-in limit, reset after window, retry-after header, path-specific limits, and non-special-rule limits.
- [x] Add tests for custom rules, disabled rules, custom storage, secondary storage, TTL handling, and storage values in milliseconds.
- [x] Add tests for configured IP headers, IPv6 subnet normalization, disabled IP tracking, and fallback behavior.
- [x] Run router tests.

### Task 6: Final Verification

**Files:**
- Modify: `.docs/plans/2026-04-30-core-api-router-upstream-parity.md`
- Modify: `.docs/plans/2026-04-29-core-upstream-test-parity.md`

- [x] Mark upstream API/router rows as `Ported` or `Ruby exclusion documented`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec rake test`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec standardrb`.

## Completion Notes

- `api/to-auth-endpoints.test.ts`: Ported Ruby-applicable endpoint conversion, hook mutation, response/header/cookie, disabled path, trusted proxy, dynamic base URL, custom status, and APIError header behavior into `api_test.rb`, `endpoint_test.rb`, and `router_test.rb`. Debug stack trace and cross-realm Request cases are JavaScript runtime-specific exclusions.
- `api/index.test.ts`: Ported Ruby-applicable context preparation, plugin `on_request` chain ordering/replacement/short-circuiting, and trailing slash behavior. Promise-based context resolution is adapted to Ruby's synchronous context preparation.
- `api/check-endpoint-conflicts.test.ts`: Ported conflict matrix, including wildcard and method-array cases, duplicate endpoints in one plugin, pathless endpoints, and logger shape.
- `api/middlewares/origin-check.test.ts`: Ported safe-method behavior, trusted/untrusted origins, malformed and missing origin handling, callback variants, relative path policy, Fetch Metadata coverage, flag separation, and path-scoped origin skipping.
- `api/rate-limiter/rate-limiter.test.ts`: Ported special/default/custom rule behavior, path-key behavior, retry headers, storage reset/TTL/millisecond handling, disabled rules, missing-IP warning, and IP normalization boundaries.
