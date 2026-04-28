# Feature: SCIM Plugin

**Upstream Reference:** `upstream/packages/scim/src/index.ts`, `upstream/packages/scim/src/routes.ts`, `upstream/packages/scim/src/middlewares.ts`, `upstream/packages/scim/src/scim-filters.ts`, `upstream/packages/scim/src/patch-operations.ts`, `upstream/packages/scim/src/mappings.ts`, `upstream/packages/scim/src/scim-resources.ts`, `upstream/packages/scim/src/scim-metadata.ts`, `upstream/packages/scim/src/scim-tokens.ts`, `upstream/packages/scim/src/user-schemas.ts`, `upstream/packages/scim/src/scim.test.ts`

## Summary

Adds `BetterAuth::Plugins.scim` with token generation, Bearer token middleware, SCIM v2 metadata endpoints, and basic user provisioning routes.

Status: Extracted to `better_auth-scim`.

## Package Boundary

SCIM is provisioning, not login. It can be used alongside SSO in enterprise deployments, but it does not depend on SSO and SSO does not depend on SCIM.

To match upstream `@better-auth/scim`, Ruby SCIM lives in `better_auth-scim`.

## Ruby Adaptation

- Implemented in `packages/better_auth-scim` as a plugin package.
- Adds `scimProvider` schema fields: `providerId`, `scimToken`, and `organizationId`.
- Extends user schema with `active` and `externalId` for SCIM provisioning.
- Adds `/scim/generate-token`, `/scim/v2/Users`, `/scim/v2/Users/:userId`, `/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas`, `/scim/v2/Schemas/:schemaId`, `/scim/v2/ResourceTypes`, and `/scim/v2/ResourceTypes/:resourceTypeId`.
- Supports upstream base64url SCIM token envelopes with provider and optional organization binding.
- Supports plain, SHA-256 hashed, encrypted, custom hash, and custom encrypt/decrypt token storage.
- Creates SCIM provider accounts for provisioned users, links existing users by email, scopes list/get/update/patch/delete by provider, and enforces organization membership for organization-scoped tokens.
- Supports primary email selection, formatted/given/family name mapping, external ID/account ID mapping, slash and dot PATCH paths, and no-path value object PATCH operations.

## Key Differences

- Filter support follows upstream server behavior for `userName eq` and `externalId eq`, including linked-account `externalId` values and intentional SCIM-style errors for unsupported operators (`ne`, `co`, `sw`, `ew`, and `pr`).
- Organization-scoped provisioning requires the organization plugin and rejects token generation or resource access when the authenticated user/resource is outside the organization.

## Testing

```bash
cd packages/better_auth
cd ../better_auth-scim
rbenv exec bundle exec ruby -Itest test/better_auth/scim_test.rb
```
