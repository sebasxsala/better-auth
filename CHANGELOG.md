# Changelog

This repository contains independently versioned Ruby packages. Package-specific
release notes live in each package's `CHANGELOG.md`.

## 2026-04-29

### Release candidates

- `better_auth` `0.3.0`: upstream v1.6.9 parity for social providers, OAuth/OIDC protocol behavior, routes, schemas, adapters, and plugin hooks.
- `better_auth-rails` `0.2.1`: Active Record adapter falsey-value lookup and JSON/array migration type fixes.
- `better_auth-api-key` `0.2.0`: upstream v1.6.9 API key behavior, route shapes, metadata, permissions, expiration, and rate-limiting parity.
- `better_auth-hanami` `0.1.1`: route generator, mounted path, migration type, and Sequel adapter fixes.
- `better_auth-oauth-provider` `0.2.0`: upstream v1.6.9 OAuth provider behavior for dynamic clients, consent, token, discovery, userinfo, revocation, and session flows.
- `better_auth-passkey` `0.2.0`: upstream server parity for passkey registration, authentication, credential metadata, verification, and origin handling.
- `better_auth-redis-storage` `0.2.0`: upstream-shaped Redis storage builders, optional `SCAN` support, and expanded compatibility coverage.
- `better_auth-scim` `0.2.0`: upstream SCIM provisioning parity for users, groups, filters, patch operations, schema responses, and token behavior.
- `better_auth-sinatra` `0.1.1`: mounted base-path, session helper, and migration dialect normalization fixes.
- `better_auth-sso` `0.2.0`: upstream SSO parity for OIDC, SAML, organization flows, metadata, account linking, and error shapes.
- `better_auth-stripe` `0.2.0`: upstream Stripe parity for checkout, portal, subscriptions, webhooks, customers, and organization billing.

### Held

- `better_auth-mongo-adapter` remains at `0.1.0`; it is documented for a future first publish but was not version-bumped with this release set.
