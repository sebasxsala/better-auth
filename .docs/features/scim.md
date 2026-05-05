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
- Adds `scimProvider` schema fields: `providerId`, `scimToken`, `organizationId`, and optional `userId` for upstream provider ownership.
- Extends user schema with `active` and `externalId` for SCIM provisioning.
- Adds `/scim/generate-token`, `/scim/list-provider-connections`, `/scim/get-provider-connection`, `/scim/delete-provider-connection`, `/scim/v2/Users`, `/scim/v2/Users/:userId`, `/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas`, `/scim/v2/Schemas/:schemaId`, `/scim/v2/ResourceTypes`, and `/scim/v2/ResourceTypes/:resourceTypeId`.
- Supports upstream base64url SCIM token envelopes with provider and optional organization binding.
- Supports plain, SHA-256 hashed, encrypted, custom hash, and custom encrypt/decrypt token storage.
- Creates SCIM provider accounts for provisioned users, links existing users by email, scopes list/get/update/patch/delete by provider, and enforces organization membership for organization-scoped tokens.
- Enforces upstream role-gated organization token generation and provider management. The default privileged roles are `admin` and the organization creator role. `provider_ownership: {enabled: true}` restricts personal provider management to the owner while leaving legacy ownerless providers readable for compatibility.
- Supports primary email selection, formatted/given/family name mapping, external ID/account ID mapping, slash and dot PATCH paths, and no-path value object PATCH operations.
- New SCIM-created users keep the core default `emailVerified: false`, matching upstream; existing users linked by SCIM keep their current verification state.

## Key Differences

- Ruby canonicalizes SCIM email/userName values to lowercase before persisting the user email. When `externalId` is omitted, Ruby also uses the lowercase userName as the SCIM account `accountId`; upstream preserves the original userName casing for that account id fallback.
- Filter support follows upstream server behavior for `userName eq`, including intentional SCIM-style errors for unsupported attributes such as `externalId` and unsupported operators (`ne`, `co`, `sw`, `ew`, and `pr`).
- Organization-scoped provisioning requires the organization plugin and rejects token generation or resource access when the authenticated user/resource is outside the organization.
- `default_scim` entries are checked before database-backed SCIM providers. A static provider with the same `providerId` as a database provider takes precedence and the database token will be rejected.

## Filter Support

The Ruby port intentionally supports the same narrow upstream filter subset for
`GET /scim/v2/Users`: `userName eq "value"`. The value is matched against the
canonicalized user email. Unsupported attributes such as `externalId` and
unsupported operators (`ne`, `co`, `sw`, `ew`, and `pr`) raise SCIM
`invalidFilter` errors instead of silently widening the query.

## Operational Database Recommendations

SCIM provisioning maps IdP identities through Better Auth account rows using the
provider id and external account id. Production apps should enforce uniqueness
for that identity pair, for example a unique SQL index on `providerId` and
`accountId` for account rows, or the equivalent invariant in MongoDB.

SCIM provider ids are globally unique in the plugin schema. Production apps
should also enforce uniqueness for `scimProvider.providerId`, which prevents
ambiguous management lookups and matches upstream schema semantics. Concrete DDL
belongs in the application's migration for its selected adapter; the SCIM gem
documents the invariant but does not install every adapter-specific index.

## Testing

```bash
cd packages/better_auth
cd ../better_auth-scim
rbenv exec bundle exec ruby -Itest test/better_auth/scim_test.rb
```
