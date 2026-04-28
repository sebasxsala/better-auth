# Feature: OpenAPI Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/open-api/index.ts`, `upstream/packages/better-auth/src/plugins/open-api/generator.ts`, `upstream/packages/better-auth/src/plugins/open-api/open-api.test.ts`

## Summary

Generates an OpenAPI 3.1 document for configured auth routes and serves a Scalar reference page.

Status: Partial. Ruby now matches several server-visible pieces of upstream OpenAPI output, but it is not yet exact upstream snapshot parity.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.open_api`.
- Implements `/open-api/generate-schema` and configurable reference path, defaulting to `/reference`.
- Generates model schemas from `BetterAuth::Schema.auth_tables`.
- Emits route entries from base and plugin endpoints, excluding hidden/server-only endpoints and the OpenAPI plugin's own private endpoints from the generated public document.
- Emits upstream-compatible OpenAPI 3.1.1 document metadata, security schemes, global security, server URL, default tag metadata, default error responses, and `:param` to `{param}` path conversion.
- Represents upstream Zod-derived request-body behavior through the generated Ruby schema contract for server-relevant routes, including nested `idToken`, OpenAPI 3.1 nullable arrays, defaulted `rememberMe`, and boolean optional fields.
- Preserves model field defaults, generated-at-runtime defaults, `readOnly` fields, date-time formats, required fields, and additional user fields.

## Notes

Upstream derives endpoint schemas from endpoint metadata and Zod objects. Ruby does not expose Zod internals today, and the generator still hand-authors only selected request bodies and generic/default response shapes. Therefore OpenAPI must remain `Partial` until every server-relevant endpoint in `upstream/packages/better-auth/src/plugins/open-api/__snapshots__/open-api.test.ts.snap` is represented by equivalent Ruby metadata or by a documented, tested Ruby schema source.

Remaining parity gaps:

- Full snapshot parity for every base and plugin path, including rich request and response schemas beyond the currently covered email/social auth routes.
- Automatic query/body schema extraction from endpoint declarations rather than a small route-specific metadata table.
- Exact operation metadata for all upstream documented endpoints, including descriptions, `operationId`, custom response codes, enums, formats, object strictness, and `$ref` usage.
- Exact Scalar reference HTML/configuration parity, including the upstream embedded configuration and favicon payload.

2026-04-28 correction: previous wording overstated this as complete. The improved generator and tests should stay, but the status remains partial until the gaps above are closed.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/open_api_test.rb
```
