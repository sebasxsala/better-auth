# Upstream and Product Alignment Backlog

This file is a parking lot, not a release commitment. Items here need product
decisions, upstream coordination, certification-oriented planning, or larger
cross-package work before they should become implementation tasks.

## SSO

- `private_key_jwt` client authentication
  Deferred until the OAuth/SAML public surface and supported signing algorithms
  are agreed across Ruby and upstream behavior.
- mTLS support
  Deferred because certificate validation belongs partly to Rack/proxy
  deployment and partly to auth policy.
- Lazy `ruby-saml` loading
  Deferred as dependency-shaping work; current behavior favors explicit package
  capabilities over load-order churn.
- `disable_implicit_sign_up` parity
  Deferred because changing sign-up/linking behavior is a product decision.
- Deeper SLO/XML edge-case coverage
  Deferred for a SAML-specific certification plan rather than README-level
  cleanup.

## SCIM

- RFC list pagination
  Deferred until list semantics, total count behavior, and adapter limits are
  designed together.
- Group and Bulk endpoints
  Deferred as product expansion beyond the current user provisioning surface.
- `delete_user` vs unlink-only delete semantics
  Deferred because it changes data-retention behavior across adapters.
- Advanced filters
  Deferred until parser scope and SCIM certification goals are agreed.

## Passkey / WebAuthn

- Optional user-verification policy change
  Deferred because stricter UV defaults would diverge from upstream unless it is
  exposed as an explicit option.
- Attestation beyond `none`
  Deferred until relying-party policy, attestation formats, and WebAuthn gem
  support are scoped.
- Verify-route 401/400 policy
  Deferred because changing all verification failures to 401 affects clients.
- `deviceType` string parity
  Deferred because Ruby's WebAuthn gem exposes different runtime objects than
  the TypeScript/SimpleWebAuthn stack.
- User-handle byte-for-byte parity
  Deferred until there is a compatibility test matrix with upstream clients.

## Redis Storage

- Dedicated error taxonomy
  Deferred until storage errors are handled consistently across secondary
  storage implementations.
- Redis Cluster test matrix
  Deferred as operational CI infrastructure rather than gem API behavior.
- Sub-second TTL parity
  Deferred because Redis command choice and upstream fractional TTL behavior
  need explicit compatibility requirements.
- Breaking `key_prefix: ""` default changes
  Deferred because existing apps may rely on the current verbatim prefix
  behavior.

## Routing / Sinatra / Multi-DB

- Session-level Bearer validation for arbitrary routes
  Deferred until core session/router APIs define how non-cookie auth attaches to
  framework helper contexts.
- Shared `MountedApp` extraction
  Deferred until Rails, Hanami, and Sinatra mount behavior can be proven with
  integration tests.
- Portable primary-key DDL rewrite
  Deferred because SQL adapters need a shared migration strategy.
- Native UUID migration columns
  Deferred until app migration defaults and adapter mappings are release-scoped.

## Core

- `debugLogs` parity
  Deferred because Ruby needs an explicit logging API shape instead of a thin TS
  option copy.
- Strict `OptionBuilder` validation
  Deferred because plugins and custom options currently depend on passthrough.
- Database sharding
  Deferred as a larger adapter contract discussion.
- Global negative-path QA policy
  Deferred until package-level test strategy is agreed.
- Secret default hardening
  Deferred until there is a migration and release story for existing apps.
