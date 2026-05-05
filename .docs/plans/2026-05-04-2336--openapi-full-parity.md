# OpenAPI Full Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` or `subagent-driven-development`. Update this plan's checkboxes as phases complete and record any Ruby-specific upstream adaptation.

**Goal:** Move OpenAPI from `Partial` to `Supported` by reaching upstream `v1.6.9` base-schema parity, rich Ruby plugin endpoint schemas, and matching Scalar reference behavior.

**Architecture:** Keep runtime auth behavior unchanged. Make OpenAPI generation richer through endpoint metadata and small `BetterAuth::OpenAPI` helpers, using upstream snapshot output as the contract for base routes and a Ruby-defined completeness contract for implemented plugins.

**Tech stack:** Ruby, Rack, Minitest, StandardRB, upstream Better Auth `v1.6.9`.

---

## Summary

- [x] Match upstream base OpenAPI snapshot for public paths, operation metadata, parameters, request bodies, response schemas, defaults, formats, nullable shapes, and error responses.
- [x] Add rich OpenAPI metadata for every visible Ruby core plugin endpoint that is included in generated docs.
- [x] Port upstream Scalar HTML configuration closely enough that theme, nonce, favicon, metadata, and embedded schema behavior match.
- [x] Update docs and feature notes so `OpenAPI` can be marked `Supported` only after tests prove the contract.

## Implementation Changes

- [x] **Baseline:** Read `AGENTS.md`, `packages/better_auth/AGENTS.md`, `upstream/packages/better-auth/src/plugins/open-api/generator.ts`, and `upstream/.../__snapshots__/open-api.test.ts.snap`; run `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/open_api_test.rb`.
- [x] **Test harness:** Extend `packages/better_auth/test/better_auth/plugins/open_api_test.rb` with grouped assertions for upstream base paths. Assert inventory first: include `/ok` and `/error`; exclude `/open-api/generate-schema`, `/reference`, and Ruby-only `/set-password` from generated OpenAPI unless an upstream source proves it is public.
- [x] **Schema helpers:** Expand `packages/better_auth/lib/better_auth/plugins/open_api.rb` helper APIs for object, array, enum, nullable OpenAPI 3.1 type arrays, `$ref`, JSON response/request, query/path parameters, and common status/success/error responses. Keep helpers internal to `BetterAuth::OpenAPI`; do not document them as stable public API.
- [x] **Base route parity:** Update metadata in `packages/better_auth/lib/better_auth/routes/*.rb` so every upstream base route has exact rich schemas where applicable: account, callback, email verification, error, ok, password, session, sign-in, sign-out, sign-up, social, update-user, and update-session.
- [x] **Generator behavior:** Adjust path inclusion and operation generation in `open_api.rb` to match upstream semantics: skip server-only endpoints, include upstream hidden-but-documented base endpoints (`/ok`, `/error`), preserve disabled path filtering, convert `:id` to `{id}`, and emit empty POST bodies only where upstream emits them.
- [x] **Plugin schema completeness:** For core Ruby plugins with visible endpoints, ensure each generated operation has `operationId`, useful description, input metadata, and meaningful response schema or redirect response. Cover at least admin, anonymous, device authorization, dub, email OTP, expo, generic OAuth, JWT, magic link, MCP, multi-session, OAuth proxy, OIDC provider, one tap, one-time token, organization, phone number, SIWE, two-factor, and username.
- [x] **Scalar reference:** Port upstream reference HTML configuration: embedded API JSON, `configuration` dataset, favicon logo payload, `metaData`, theme default, and CSP nonce placement. Keep the CDN script source unchanged unless upstream differs.
- [x] **Docs:** Update `.docs/features/open-api.md`, `.docs/features/upstream-parity-matrix.md`, `docs/content/docs/supported-features.mdx`, `docs/content/docs/plugins/open-api.mdx`, and `docs/content/docs/introduction.mdx` after tests pass. Mark `OpenAPI` as `Supported` only if base parity and plugin schema completeness are verified.

## Test Plan

- [x] Add failing Minitest assertions for the current known gaps: `/ok` and `/error` inclusion, `/set-password` OpenAPI omission, rich schemas for remaining base paths, exact Scalar configuration, and no generic `{}` success response for routes with known response shapes.
- [x] Add plugin coverage test that builds representative core plugins and asserts every visible plugin endpoint has non-empty `operationId`, description, and either a meaningful JSON response schema or a documented redirect response.
- [x] Run focused tests: `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/plugins/open_api_test.rb`.
- [x] Run related validation tests: `cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/endpoint_test.rb`.
- [x] Run package verification: `cd packages/better_auth && rbenv exec bundle exec rake test && rbenv exec bundle exec standardrb`.

## Assumptions

- "Complete parity" means exact upstream snapshot parity for base OpenAPI output plus complete rich schemas for implemented Ruby plugin endpoints; upstream has no plugin snapshot covering every Ruby plugin.
- This plan does not remove or change runtime routes. If `/set-password` remains a Ruby runtime endpoint, it is treated as a Ruby-specific extension and excluded from OpenAPI to match upstream snapshot unless implementation discovery proves otherwise.
- No gem version bump is needed unless this work is released.

## Implementation Notes

- Ruby-specific adaptation: `/set-password` remains callable at runtime and keeps endpoint metadata for direct server API validation, but `open_api_paths` excludes it from generated OpenAPI to match upstream v1.6.9's public snapshot.
- Hidden base routes with OpenAPI metadata are now included, which brings `/ok` and `/error` into the generated document while keeping hidden plugin discovery/metadata endpoints out.
- Redirect-only plugin endpoints are treated as complete when they provide an operation id, description, and a documented 3xx response; JSON endpoints must provide a meaningful JSON schema.

## Verification Log

- `rbenv exec bundle exec ruby -Itest test/better_auth/plugins/open_api_test.rb` before changes: `19 runs, 386 assertions, 0 failures`.
- New OpenAPI parity tests failed before implementation for `/ok`, `/error`, `/set-password`, Scalar configuration, account-info schema, and visible plugin metadata.
- `rbenv exec bundle exec ruby -Itest test/better_auth/plugins/open_api_test.rb` after implementation: `22 runs, 404 assertions, 0 failures`.
- `rbenv exec bundle exec ruby -Itest test/better_auth/endpoint_test.rb`: `10 runs, 90 assertions, 0 failures`.
- `rbenv exec bundle exec rake test`: `829 runs, 4368 assertions, 0 failures`.
- `rbenv exec bundle exec standardrb`: passed after one style-only test helper fix.
