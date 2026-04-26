# Feature: SCIM Plugin

**Upstream Reference:** `upstream/packages/scim/src/index.ts`, `upstream/packages/scim/src/routes.ts`, `upstream/packages/scim/src/middlewares.ts`, `upstream/packages/scim/src/scim-filters.ts`, `upstream/packages/scim/src/patch-operations.ts`, `upstream/packages/scim/src/mappings.ts`, `upstream/packages/scim/src/scim-resources.ts`, `upstream/packages/scim/src/scim-metadata.ts`, `upstream/packages/scim/src/scim-tokens.ts`, `upstream/packages/scim/src/user-schemas.ts`, `upstream/packages/scim/src/scim.test.ts`

## Summary

Adds `BetterAuth::Plugins.scim` with token generation, Bearer token middleware, SCIM v2 metadata endpoints, and basic user provisioning routes.

## Ruby Adaptation

- Implemented inside the core gem as a plugin.
- Adds `scimProvider` schema fields: `providerId`, `scimToken`, and `organizationId`.
- Extends user schema with `active` and `externalId` for SCIM provisioning.
- Adds `/scim/generate-token`, `/scim/v2/Users`, `/scim/v2/Users/:userId`, `/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas`, `/scim/v2/Schemas/:schemaId`, `/scim/v2/ResourceTypes`, and `/scim/v2/ResourceTypes/:resourceTypeId`.
- Supports plain, SHA-256 hashed, and custom callable token storage.

## Key Differences

- Current filter support covers validated `field eq "value"` cases for `userName` and `externalId`.
- PATCH support covers server-tested `replace`, `add`, and `remove` operations for common fields, including slash-prefixed paths and no-path value objects; the exhaustive RFC matrix remains future polish.
- Organization-scoped provisioning is stored on the provider record but membership enforcement is deferred until the organization plugin is ported.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/scim_test.rb
```
