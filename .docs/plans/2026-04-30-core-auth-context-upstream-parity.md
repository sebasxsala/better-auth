# Core Auth Context Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the Ruby-applicable upstream auth/context/call test scenarios from Better Auth v1.6.9 into `packages/better_auth` and implement any missing behavior.

**Architecture:** Keep this audit isolated to core auth construction, configuration normalization, per-request context, trusted origins, and direct API/Rack call behavior. Add a focused upstream-parity test file for scenario translations that do not fit cleanly in existing files, and only modify core framework-agnostic classes.

**Tech Stack:** Ruby 3.2+, Minitest, Rack, existing `better_auth` memory adapter and endpoint/router APIs.

---

## Audit Summary

Upstream files in this audit:

- `upstream/packages/better-auth/src/context/create-context.test.ts` — 115 test titles
- `upstream/packages/better-auth/src/context/init.test.ts` — 5 test titles
- `upstream/packages/better-auth/src/context/init-minimal.test.ts` — 3 test titles
- `upstream/packages/better-auth/src/auth/full.test.ts` — 15 test titles
- `upstream/packages/better-auth/src/auth/minimal.test.ts` — 5 test titles
- `upstream/packages/better-auth/src/auth/trusted-origins.test.ts` — 19 test titles
- `upstream/packages/better-auth/src/call.test.ts` — 20 test titles

Existing Ruby coverage already covers the broad shape in:

- `packages/better_auth/test/better_auth/auth_test.rb`
- `packages/better_auth/test/better_auth/configuration_test.rb`
- `packages/better_auth/test/better_auth/plugin_test.rb`
- `packages/better_auth/test/better_auth/router_test.rb`
- `packages/better_auth/test/better_auth/api_test.rb`

Differences found:

- Ruby has compact tests for defaults, secrets, trusted origins, plugin init, proxy headers, and API hooks, but upstream has many individual edge cases not yet translated title-for-title.
- Kysely-specific tests are not Ruby-applicable; Ruby should document them as adapter initialization exclusions.
- Browser/client fetch calls in `call.test.ts` should be adapted to direct API and Rack request behavior, not browser client implementation.
- Dynamic `baseURL` object behavior with `allowedHosts`, fallback, per-request trusted origins, and cross-subdomain cookie domain is under-covered.
- Stateless/session cookie-cache defaults and warnings are partially covered, but upstream has finer cases for refresh-cache calculation and database/secondary-storage interactions.
- Plugin init sequencing is partially covered, but upstream has more cases for nil/empty init results, mixed sync/async ordering, repeated context mutation, plugin option default precedence, and database hook collection.
- Trusted-origin hardening is partially covered, but upstream has missing cases for relative paths, plus signs, encoded malicious values, double dash rejection, wildcard protocols, custom schemes, dynamic origins, and plugin-provided trusted origins.
- 2026-04-30 update: ported the upstream Expo/custom-scheme wildcard trusted-origin case into `configuration_test.rb`. Ruby now matches full URLs for wildcard patterns that include a scheme and path, while still matching scheme wildcards without paths against the URL origin.
- 2026-04-30 update: added `auth_context_upstream_parity_test.rb` and ported plugin-provided trusted-origin merging, empty secret fallback in test, production default-secret rejection, and stateless cookie-cache `max_age` normalization.
- 2026-04-30 update: wired dynamic `base_url`/`baseURL` allowed-host configs into Rack requests, including empty-list validation, trusted forwarded host resolution, disallowed-host errors, fallback URL, configured protocol, wildcard host patterns, and allowed-host trusted origins.
- 2026-04-30 update: ported dynamic cross-subdomain cookie domain behavior for allowed-host requests, direct API redirect errors preserving pre-set headers, and router blocking for endpoints with upstream `metadata.scope = "server"`.
- 2026-04-30 update: ported cookie-cache refresh default threshold to 20% of `max_age` and added thread-local request runtime isolation for dynamic `base_url` requests.
- 2026-04-30 update: browser client `$fetch` cases in `call.test.ts` are documented as Ruby exclusions; Ruby only ports equivalent Rack/API server behavior because the core gem has no browser client.
- Direct API/call behavior is now covered for Ruby server-side equivalents: cookie setting through hooks, redirect/header behavior, chained hook errors, global hooks, context mutation, Rack response conversion, and server-scoped endpoint calls.
- 2026-04-30 update: fixed dynamic `base_url` request runtime leakage by keeping `Configuration#base_url` request-local per thread and clearing context/config runtime state after Rack calls and before direct API calls.
- 2026-04-30 update: exposed Ruby context password utilities (`config`, `hash`, `verify`, `check_password`) backed by `BetterAuth::Password` and configured callbacks.
- 2026-04-30 update: updated `docs/content/docs/supported-features.mdx` so the audited core runtime features are marked `Supported` for Ruby server-side behavior.

## Translation Plan

Create `packages/better_auth/test/better_auth/auth_context_upstream_parity_test.rb` for upstream-title-aligned scenarios that would otherwise bloat existing tests. Keep existing tests in place; add assertions there only when the existing file already owns the behavior.

Mark these upstream cases as Ruby-specific exclusions in this plan during implementation:

- `context/init.test.ts`: Kysely adapter initialization, Kysely migrations, and Kysely dialect detection.
- `auth/minimal.test.ts`: direct database connection requiring Kysely.
- `call.test.ts`: browser client fetch semantics; adapt only the server/direct API equivalent.
- `context/create-context.test.ts`: telemetry publishing internals if this stays covered by the separate instrumentation plan.

## Tasks

### Task 1: Base URL, Base Path, Secret, And Config Defaults

**Files:**
- Modify: `packages/better_auth/test/better_auth/auth_context_upstream_parity_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/configuration.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/context.rb`

- [x] Translate upstream cases for env base URL priority, base path handling, empty/root basePath, custom paths, trailing slash normalization, baseURL with path/query/port/https, undefined/empty baseURL, and invalid protocol errors.
- [x] Translate upstream secret precedence cases: options secret, `BETTER_AUTH_SECRET`, `AUTH_SECRET`, test default secret, production default-secret rejection, empty-secret fallback, and short/low-entropy warning.
- [x] Translate session defaults: default max age/update age/fresh age, `freshAge = 0`, custom timeouts, stateless default, stateless override, and stateless cookie cache maxAge matching custom session expiry.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/auth_context_upstream_parity_test.rb`.

Progress:

- [x] Ported empty-secret fallback to test default.
- [x] Ported production rejection for the default secret.
- [x] Ported stateless cookie-cache `max_age` matching `session.expires_in`.
- [x] Ported env base URL, basePath normalization, path/query/port/HTTPS origin extraction, and invalid protocol coverage into `configuration_test.rb`.

### Task 2: Cookie Cache, Rate Limit, State Strategy, And Password Utilities

**Files:**
- Modify: `packages/better_auth/test/better_auth/auth_context_upstream_parity_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/configuration.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/cookies.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/context.rb`

- [x] Translate cookie cache cases: undefined false, explicit false, database/secondary-storage refresh-cache warning disablement, stateless refresh-cache 20% updateAge calculation, default maxAge calculation, and custom updateAge.
- [x] Translate rate-limit defaults and custom values: default window/max, explicit enabled, custom storage, and secondary-storage default selection.
- [x] Translate account state strategy cases: cookie strategy default without database, explicit cookie strategy, and skip state cookie check.
- [x] Translate password configuration cases: default length limits, custom limits, custom hash/verify callbacks, and context exposure of password utilities.
- [x] Run the focused parity test file.

Progress:

- [x] Ported stateless refresh-cache default threshold at 20% of `max_age`.
- [x] Ported context password utility exposure with Ruby callbacks.

### Task 3: Plugin Init, Plugin Defaults, Context Mutation, And Database Hooks

**Files:**
- Modify: `packages/better_auth/test/better_auth/auth_context_upstream_parity_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/plugin_registry.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/plugin_context.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/configuration.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/auth.rb`

- [x] Translate plugin init cases: no plugins, plugins without init, init returning nil/empty hash, init sequence ordering, later plugins seeing earlier modifications, multiple plugins modifying same context property, and mixed sync/Ruby callable initialization.
- [x] Translate plugin config-default precedence: plugin defaults apply when user config omitted, but never override explicitly supplied main config.
- [x] Translate database-hook collection cases: plugin hooks merge with app hooks, plugins without hooks do not error, and internal adapter is recreated after plugin init so plugin hooks are visible.
- [x] Translate endpoint conflict cases that belong to auth construction: same path different methods does not throw, same path same method logs without raising, different paths do not error.
- [x] Run focused tests plus `ruby -Itest test/better_auth/plugin_test.rb`.

### Task 4: Dynamic Base URL, Per-Request Context, And Trusted Origins

**Files:**
- Modify: `packages/better_auth/test/better_auth/auth_context_upstream_parity_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/configuration.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/context.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/cookies.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/router.rb`

- [x] Translate dynamic baseURL cases: empty allowedHosts rejection, allowed host resolution, disallowed host rejection, fallback URL, configured protocol, wildcard Vercel host patterns, and adding allowed hosts to trusted origins.
- [x] Translate per-request context isolation: concurrent requests must not leak `base_url`, `trusted_origins`, adapter/internal adapter, current session, or new session.
- [x] Translate dynamic cross-subdomain cookie domain behavior when request host is allowed.
- [x] Translate trusted origin cases: app origin always allowed, inferred baseURL origin, updated context origin, exact matches, prefix/subdomain rejection, relative path rejection/default, allowed relative paths/query/plus signs, double dash rejection, encoded malicious rejection, wildcard trusted origins, protocol-specific wildcards, Expo/custom scheme wildcard, dynamic trusted origins, rejected dynamic origins, and plugin init trusted-origin merge.
- [x] Run focused tests plus `ruby -Itest test/better_auth/auth_test.rb test/better_auth/configuration_test.rb`.

Progress:

- [x] Ported empty `allowedHosts` rejection.
- [x] Ported allowed forwarded-host resolution.
- [x] Ported disallowed host rejection without fallback.
- [x] Ported fallback URL for disallowed host.
- [x] Ported configured protocol override.
- [x] Ported Vercel/preview wildcard host patterns.
- [x] Ported adding allowed hosts and fallback to trusted origins.
- [x] Ported dynamic cross-subdomain cookie domain from the resolved request host.
- [x] Ported thread-local `base_url` isolation for parallel dynamic-host Rack requests.
- [x] Ported request-local `options.base_url` isolation and runtime cleanup after Rack calls/direct API resets.
- [x] Ported Expo/custom-scheme wildcard trusted-origin matching.
- [x] Ported plugin init trusted-origin merge with user dynamic config.

### Task 5: Direct API And Rack Call Semantics

**Files:**
- Modify: `packages/better_auth/test/better_auth/auth_context_upstream_parity_test.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/api.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/router.rb`
- Modify as needed: `packages/better_auth/lib/better_auth/endpoint.rb`

- [x] Translate server-call cases: call API endpoint, server-scoped endpoint, set cookies, before hook interception, before hook context mutation, after hook interception, after hook cookie setting, response-object return, APIError raising/response conversion, generic error raising, redirect response, redirect base headers, after hook error, chained hook error, global before/after hooks, and global before context mutation.
- [x] Adapt browser client fetch/query/cookie cases to Ruby direct API plus Rack request equivalents; document browser-only semantics as excluded.
- [x] Run focused tests plus `ruby -Itest test/better_auth/api_test.rb test/better_auth/router_test.rb`.

Progress:

- [x] Ported redirect errors preserving headers set before `ctx.redirect`.
- [x] Ported router blocking for endpoints marked with upstream `metadata.scope = "server"` while direct API calls still work.
- [x] Ported direct API hook/cookie/error-chain/global-hook server semantics from `call.test.ts`.
- [x] Documented browser-client `$fetch` tests as Ruby exclusions unless covered by Rack request equivalents.

### Task 6: Final Verification And Plan Update

**Files:**
- Modify: `.docs/plans/2026-04-30-core-auth-context-upstream-parity.md`
- Modify: `.docs/plans/2026-04-29-core-upstream-test-parity.md`
- Modify: `docs/content/docs/supported-features.mdx`

- [x] Mark each translated upstream file row with `Ported` or `Ruby exclusion documented`.
- [x] Update the master plan link/status to show this child plan is implemented, not just audited.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec rake test`.
- [x] Run `cd packages/better_auth && rbenv exec bundle exec standardrb`.
