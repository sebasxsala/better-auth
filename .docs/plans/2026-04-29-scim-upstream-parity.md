# SCIM Upstream Parity Plan

**Goal:** Bring the Ruby `better_auth-scim` package closer to the upstream `@better-auth/scim` behavior, starting with security-sensitive provider management and SCIM protocol response gaps.

**Scope:** Implement the highest-impact upstream differences discovered in the comparison pass. Preserve intentional Ruby-specific extensions only when they do not weaken upstream behavior.

- [x] Add tests for provider management endpoints, provider ownership, org role checks, token hooks, SCIM metadata shape, SCIM error shape, media types, create `Location`, and missing/anonymous access cases.
- [x] Implement `provider_ownership`, `required_role`, role parsing, provider access checks, and provider connection management endpoints.
- [x] Implement `before_scim_token_generated` and `after_scim_token_generated` callbacks around token persistence.
- [x] Add SCIM error response helpers and use them for SCIM bearer-protected endpoints and SCIM metadata/not-found/filter errors.
- [x] Align metadata endpoints with upstream `ServiceProviderConfig`, `Schemas`, and `ResourceTypes` response shapes.
- [x] Add `application/scim+json` media type support for SCIM user endpoints and `Location` on create.
- [x] Port additional upstream SCIM tests for validation, canonicalized `userName`, full create resource shape, PATCH default `op`, idempotent `add`, standalone provider listing, invalid provider IDs, anonymous management calls, hook aborts, and provider ownership regeneration.
- [x] Align `default_scim` precedence with upstream so configured default providers reject mismatched tokens before falling back to stored providers.
- [x] Wrap SCIM create/update user mutations in adapter transactions and update account/user timestamps on PUT/PATCH.
- [x] Expand SCIM User schema metadata descriptions to match upstream response shape.
- [x] Add Ruby plugin surface parity for `version`, `client`/`scim-client`, and OpenAPI `hide` metadata on SCIM protocol endpoints.
- [x] Align documented Ruby docs/README with implemented options and routes.
- [x] Run focused SCIM tests and Standard lint for both the SCIM gem and touched core router.

Remaining notes:

- [ ] A literal one-test-per-upstream-`it` translation is not complete; Ruby now covers the behavior with grouped tests.
- [x] Ruby now exposes equivalent metadata for `scimClient()` and `HIDE_METADATA` in the Ruby plugin surface.
