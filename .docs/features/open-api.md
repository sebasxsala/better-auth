# Feature: OpenAPI Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/open-api/index.ts`, `upstream/packages/better-auth/src/plugins/open-api/generator.ts`, `upstream/packages/better-auth/src/plugins/open-api/open-api.test.ts`

## Summary

Generates an OpenAPI 3.1 document for configured auth routes and serves a Scalar reference page.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.open_api`.
- Implements `/open-api/generate-schema` and configurable reference path, defaulting to `/reference`.
- Generates model schemas from `BetterAuth::Schema.auth_tables`.
- Emits route entries from base and plugin endpoints.

## Notes

The upstream generator derives rich schemas from Zod metadata. Ruby currently produces a practical OpenAPI 3.1 skeleton with model fields and selected request-body hints; exhaustive snapshot parity remains future work.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/open_api_test.rb
```
