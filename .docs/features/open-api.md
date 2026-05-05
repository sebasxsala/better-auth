# Feature: OpenAPI Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/open-api/index.ts`, `upstream/packages/better-auth/src/plugins/open-api/generator.ts`, `upstream/packages/better-auth/src/plugins/open-api/open-api.test.ts`

## Summary

Generates an OpenAPI 3.1 document for configured auth routes and serves a Scalar reference page.

Status: Supported. Ruby now covers the upstream OpenAPI document contract for base routes and the generated Ruby contract for visible server plugin endpoints.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.open_api`.
- Implements `/open-api/generate-schema` and configurable reference path, defaulting to `/reference`.
- Generates model schemas from `BetterAuth::Schema.auth_tables`.
- Emits route entries from base and plugin endpoints, excluding server-only endpoints and the OpenAPI plugin's own private endpoints from the generated public document while keeping upstream hidden-but-documented `/ok` and `/error` paths.
- Emits upstream-compatible OpenAPI 3.1.1 document metadata, security schemes, global security, server URL, default tag metadata, default error responses, and `:param` to `{param}` path conversion.
- Represents upstream Zod-derived request/response behavior through the generated Ruby schema contract for server-relevant routes, including nested objects, OpenAPI 3.1 nullable arrays, defaulted booleans, path/query parameters, custom response codes, and richer response schemas.
- Preserves model field defaults, generated-at-runtime defaults, `readOnly` fields, date-time formats, required fields, and additional user fields.
- Serves the Scalar reference page with upstream-style embedded configuration, metadata, theme, favicon, and CSP nonce support.

## Notes

Upstream derives endpoint schemas from endpoint metadata and Zod objects. Ruby does not expose Zod internals, so the Ruby port uses explicit endpoint metadata and `BetterAuth::OpenAPI` helper methods as the schema source. This is a Ruby-specific adaptation: generated output is tested against the upstream base-route contract and against the Ruby plugin endpoint contract rather than relying on runtime Zod introspection.

Known Ruby-specific differences:

- `/set-password` remains a callable Ruby server endpoint but is excluded from generated OpenAPI output because upstream `setPassword` has no public OpenAPI path in the v1.6.9 snapshot.
- Plugin endpoint parity is defined by visible Ruby server endpoints having operation metadata and meaningful response schemas. Upstream does not provide one complete plugin snapshot covering every Ruby plugin package boundary.

2026-04-28 correction: previous wording overstated this as complete before route schema parity was verified. The status is now complete after the 2026-05-04 OpenAPI parity pass.

2026-05-04 progress: upstream `open-api.test.ts.snap` includes 30 base paths. Ruby now emits the same public base-path inventory, excludes the Ruby-only `/set-password` route from generated OpenAPI, includes rich schemas for the previously generic base paths, verifies visible core plugin endpoints have rich metadata, and serves Scalar with upstream-style configuration.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/open_api_test.rb
```
