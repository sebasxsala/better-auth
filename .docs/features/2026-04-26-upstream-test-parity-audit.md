# Upstream Test Parity Audit - 2026-04-26

Read-only audit of the current Ruby Better Auth port against upstream Better Auth tests and behavior.

## Scope

- Repository: `/Users/sebastiansala/projects/better-auth`
- Upstream source of truth: `upstream/packages/better-auth/src`
- Extra upstream package noted: `upstream/packages/passkey/src`
- Local core tests: `packages/better_auth/test`
- Local Rails tests: `packages/better_auth-rails/spec`
- Coordination: 10 explorer subagents were launched across independent areas: core pipeline, persistence, security/session primitives, base routes, plugin groups, Rails adapter, test inventory, and docs parity.

This audit did not intentionally modify implementation code. It creates this summary document only.

## Test Inventory

Confirmed: the upstream Better Auth folder has tests.

| Inventory | Count |
| --- | ---: |
| Upstream test files under `upstream/packages/better-auth/src/**/*.test.ts(x)` | 87 |
| Local core Minitest files under `packages/better_auth/test/**/*_test.rb` | 47 |
| Local Rails spec files under `packages/better_auth-rails/spec/**/*_spec.rb` | 8 |
| Local Ruby/Rails test files total | 55 |
| Approximate upstream suites with a direct or consolidated Ruby counterpart | 51 |
| Approximate upstream suites deferred or not applicable to Ruby server core | 19 |
| Approximate upstream suites with no Ruby counterpart because the feature is not implemented | 17 |

Upstream test distribution under `upstream/packages/better-auth/src`:

| Area | Test files |
| --- | ---: |
| `plugins` | 35 |
| `adapters` | 15 |
| `api` including routes/middleware/rate limit | 14 |
| `db` | 5 |
| `client` | 5 |
| `auth` | 3 |
| `context` | 3 |
| `cookies`, `crypto`, `oauth2`, `social`, `types`, `utils`, `call` | 7 combined |

Local core distribution under `packages/better_auth/test/better_auth`:

| Area | Test files |
| --- | ---: |
| `plugins` | 18 |
| `routes` | 11 |
| `adapters` | 5 |
| Core single-file suites | 13 |

## Local Test Execution

Commands attempted:

```sh
bundle exec rake test
bundle exec rspec
```

Both failed immediately with the system Ruby 2.6 Bundler because Bundler 2.5.22 was not available. Retried with the repo's expected Ruby via `rbenv exec`.

```sh
rbenv exec bundle exec rake test
```

Result:

- `212 runs, 1025 assertions, 0 failures, 1 errors, 3 skips`
- Error: `BetterAuthPostgresAdapterTest#test_postgres_adapter_can_be_instantiated_without_rails`
- Cause: PostgreSQL connection to `::1` / `127.0.0.1:5432` failed with `Operation not permitted` in this sandbox.

```sh
rbenv exec bundle exec rspec
```

Result:

- `12 examples, 1 failure`
- Failure: `BetterAuth::Rails PostgreSQL integration`
- Cause: PostgreSQL connection to `::1` / `127.0.0.1:5432` failed with `Operation not permitted` in this sandbox.

One subagent also ran the implemented Group B plugin suite:

- `40 runs, 201 assertions, 0 failures`

Interpretation: the local suites are mostly executable, but full verification is blocked here by sandboxed PostgreSQL TCP access. The failures observed are environment-access failures, not assertion failures in product behavior.

## Executive Verdict

The Ruby port has a substantial skeleton and many happy-path tests, but it is not yet upstream-parity-complete. The strongest coverage is around the Rack endpoint/router shape, basic email auth flows, memory/schema foundations, and several server-side plugin cores. The biggest gaps are security/session edge cases, OAuth/social linking rules, account cookie behavior, SQL/ActiveRecord adapter contract parity, JWT rotation, OpenAPI snapshot parity, and several unimplemented upstream plugins.

The most important issue is not just "missing tests"; in several areas the current Ruby logic appears materially different from upstream Better Auth behavior. Those areas should be fixed or explicitly documented as accepted Ruby adaptations before marking phases/plugins as complete.

## Highest-Priority Findings

### P1 - BCrypt long-password truncation

Ruby hashes passwords with BCrypt in `packages/better_auth/lib/better_auth/password.rb`. Upstream uses scrypt over normalized input and has tests for very long passwords. BCrypt only considers the first 72 bytes, so two long passwords that differ after that boundary can verify as the same password.

Resolved 2026-04-27: `BetterAuth::Password` now pre-hashes password input with SHA-256 before BCrypt for new hashes, keeps legacy raw BCrypt verification, and covers upstream-equivalent long-password, unique-salt, case-sensitive, and Unicode tests.

### P1 - Session cookie cache stores unfiltered fields

`Cookies.set_cookie_cache` serializes full `session` and `user` hashes into `session_data` in `packages/better_auth/lib/better_auth/cookies.rb`. Upstream filters fields marked `returned: false` before writing cookie cache. With compact/JWT strategies, this can expose fields client-side; with encrypted strategy, it still persists fields upstream intentionally strips.

Recommended action: add a schema field with `returned: false` and assert it is absent from all cache strategies.

### P1 - `rememberMe: false` can become persistent after refresh

`Session.find_current` refreshes sessions based on `update_age`, and `refresh_session` writes a persistent session cookie. Upstream uses the `dont_remember` cookie to avoid turning a browser-session cookie into a persistent cookie.

Recommended action: add route-level tests for sign-in with `rememberMe: false`, then session refresh.

### P1 - GET callback URL origin checks are missing

`OriginCheck` skips `GET`, but upstream attaches callback URL validation to callback-bearing GET routes. Ruby then redirects user-controlled callback values in reset-password, verify-email, and delete-user callback routes.

Risk: open redirect / trusted-origin parity gap.

Recommended action: validate callback URLs on all endpoints that consume `callbackURL`, even when method is `GET`.

### P1 - Social/OAuth linking rules are incomplete

Base social flow in `packages/better_auth/lib/better_auth/routes/social.rb` is much thinner than upstream:

- OAuth state does not store `codeVerifier`, yet callback reads it.
- Existing users can be implicitly linked without upstream checks for trusted providers, verified email, `accountLinking.enabled`, or `disableImplicitLinking`.
- Social sign-in can create users even when upstream would block `disableImplicitSignUp` / `disableSignUp` unless `requestSignUp` allows it.
- New social users always redirect to `callbackURL`, not `newUserCallbackURL`.
- POST callback is handled directly rather than redirecting to GET.
- Linked accounts do not get the upstream token update / email verified upgrade / account cookie behavior.
- `/link-social` supports only direct ID-token linking, not OAuth redirect linking.

Recommended action: make social/OAuth a dedicated parity phase before calling base auth routes complete.

### P1 - Email change flow is materially incomplete

Upstream supports old-email confirmation, new-email verification, requestType branching, unauthorized-session checks, hooks, legacy flow, and session/secondary-storage propagation. Ruby currently creates one change-email verification token and then `verify_email` updates email verification state directly for `updateTo`.

Recommended action: port the upstream email-change state machine and tests as a focused chunk.

### P1 - Password reset can leak sender failures for existing users

Upstream tests that email sender failure still returns the generic password-reset success message. Ruby directly calls the sender for existing users, so an exception would occur only for existing accounts and can leak account existence.

Recommended action: wrap reset sender failures to preserve the no-enumeration response.

### P1 - Account cookie / encrypted OAuth token behavior is not ported

Upstream account routes read account cookies, encrypt/decrypt OAuth tokens, refresh account cookies, chunk account cookies when configured, and support account cookie fallback. Ruby reads adapter accounts directly and stores/passes raw tokens.

Recommended action: split account follow-up into two tracks: OAuth/link-social parity and account-cookie/encrypted-token parity.

### P1 - SQL adapter contract gaps

The SQL adapter is started but does not yet match upstream adapter contract behavior:

- MySQL update/delete affected-row handling looks unsafe.
- SQL ignores `connector: "OR"` and always joins where clauses with `AND`.
- SQL does not reject `input: false` fields on create/update.
- Joins hardcode `user_id` and support only a small subset of upstream joins.
- Secondary-storage lookup does not fall back to DB when `store_session_in_database` is enabled.
- Secondary-storage active sessions are not deduplicated.

Recommended action: create a shared Ruby adapter contract suite and run it against Memory, Postgres, MySQL, and ActiveRecord.

### P1 - Rails mounted routes likely break path matching

Rails `mount` normally strips the mount prefix from `PATH_INFO` and moves it into `SCRIPT_NAME`. The core router expects `PATH_INFO` to include `base_path` unless configured otherwise. `better_auth at: "/api/auth"` may therefore produce `/ok` for the Rack app while the core router expects `/api/auth/ok`.

Recommended action: add a full Rails request spec for `GET /api/auth/ok` and a real auth route.

### P1 - JWT rotation is not implemented

Ruby has JWKS schema/options, but it selects one latest key and returns one key. Upstream `plugins/jwt/rotation.test.ts` covers rotation after `rotationInterval`, old-key grace period, and pruning.

Recommended action: add `jwt_rotation_test.rb` before expanding JWT claims/algorithm coverage.

### P1 - OpenAPI is far from upstream snapshot parity

Ruby OpenAPI generation is a basic route/model inventory. Upstream snapshot includes rich endpoint schemas, request bodies, readOnly/default metadata, nested/nullable conversion, and detailed operation metadata.

Recommended action: decide whether the Ruby port wants snapshot parity. If yes, endpoint metadata/schema conversion must be much richer.

## Area Details

### Core factory, context, router, origin, rate limit

Covered locally:

- Auth factory shape, Rack call alias, error code merge.
- Configuration defaults and basic trusted origins.
- Endpoint result handling, raw Rack responses, cookies, redirects, API errors.
- Router base path, params, method checks, disabled paths, plugin hook chain, rate-limit smoke, origin-check smoke.

Missing or thin versus upstream:

- Plugin init ordering, option default merge, context mutation, async init equivalent, social provider filtering, `generateId`.
- Trusted origins for custom schemes and wildcard variants like `exp://10.0.0.*:*/*`.
- Dynamic trusted origins and inferred base URL behavior.
- `disable_origin_check` array coverage and deprecation behavior.
- Rate limit window reset, query params ignored in keys, plugin rules, custom callable rules, database storage, and exact `lastRequest` shape.
- Direct API redirect/header/error edge cases from `to-auth-endpoints.test.ts`.

Notable adaptation:

- Ruby secret handling is stricter outside tests than upstream. This looks intentional and safer, but should be documented as an adaptation.

### Sessions, cookies, crypto, passwords

Covered locally:

- Signed session token cookie parsing.
- Basic cookie attributes, chunk reassembly, cache version check.
- HMAC, AES-GCM helper round trip, JWT tamper rejection.
- BCrypt happy path and invalid hash.

Missing or thin versus upstream:

- Callback password tests.
- Production secure-cookie behavior and missing-secret behavior.
- Cookie cache strategies across compact/JWT/JWE.
- Invalid/tampered cache behavior through route/session lookup.
- `disableCookieCache`, `disableRefresh`, `refreshCache`, stale cache, stateless mode, secondary storage, sensitive-route cache bypass.
- Failed session refresh handling.
- Full cleanup of account-data chunks and OAuth state cookies.

Important logic mismatches:

- Password hashing now avoids BCrypt truncation for new hashes by pre-hashing input before BCrypt.
- Unfiltered cache fields.
- Dont-remember refresh behavior.
- Tampered cache can fall back to database while upstream invalidates/returns null in several paths.
- Failed adapter update during refresh can keep stale sessions alive.

### Base auth routes

Covered locally:

- Email sign-up/sign-in happy paths and several validation paths.
- Form-encoded sign-up/sign-in.
- Verification required toggles.
- Sign-out no-session behavior and session route basics.
- Password reset basic lifecycle.
- Email verification basic lifecycle.
- User update/change password/set password/delete user basics.
- Account list/unlink/get access token/refresh token/account info basics.

Missing or thin versus upstream:

- Sign-up required name schema, max password length, invalid body schema, rollback on session creation failure, same-origin/fetch/same-site CSRF allow cases.
- Sign-in disabled email/password, callback URL response/location, additional fields in response, CSRF allow matrix.
- Signed-in sign-out deletion/hook coverage.
- Full session route matrix: 39 upstream tests versus 7 local session route tests.
- Password reset sender failure no-enumeration behavior.
- Email verification/change-email requestType branching and hooks.
- Update-user allowed-field parsing, session-cookie propagation, and additional-field filtering.
- Fresh-session enforcement for delete-user.
- Password callbacks consistently used by change/set/reset/verify password.
- Account cookie and encrypted token behavior.

### Persistence and adapters

Covered locally:

- Core schema and logical camelCase field names.
- Memory adapter basics, operators, sorting, count, transaction rollback.
- SQL DDL smoke for Postgres/MySQL.
- Parameterized SQL create/find/count, logical output, basic joins.
- Internal adapter user/account/session/verification basics.
- Minimal Rails ActiveRecord adapter create/find and transaction smoke.

Missing or thin versus upstream:

- Shared adapter suite for custom model names, custom field names, nullable FKs, default values, select, all operators, OR connectors, updateMany/deleteMany complex where, update fields used in where.
- Join suite: user -> session, multiple joins, one-to-one plugin joins, missing joined rows, pagination/sort/where on joined data, custom field mappings.
- Number ID / serial behavior.
- Adapter-level auth flow suite across Memory/Postgres/MySQL/ActiveRecord.
- Migration detection/idempotency/custom schema/plugin table additions.
- Secondary-storage corrupt/missing sessions, duplicate active session entries, TTL edge cases, DB fallback.

### Implemented plugins

Stronger implemented coverage:

- `access`: runtime role/statement/resource/action checks and connector behavior.
- `additional-fields`: schema merge plus sign-up, update-user, and get-session integration.
- `admin`: user CRUD, list/search/filter/sort/count, role validation, bans, social banned callbacks, impersonation restoration, sessions, password edges, and permission checks.
- `username`: sign-up/sign-in/update/availability, duplicate/invalid, custom normalization, leak prevention.
- `anonymous`: anonymous sign-in/delete/link cleanup, generator fallbacks, and social callback cleanup.
- `magic-link`: send/verify, new-user signup, existing unverified verify, invalid/expired redirects, token storage modes.
- `bearer`: bearer session resolution, signed-token exposure, unsigned fallback, signature requirement, list-session auth, and valid-cookie fallback.
- `captcha`: protected endpoints, provider payloads, score checks, service errors, and injected verifier behavior.
- `device-authorization`: option validation, client validation, OAuth error codes/descriptions, device/user code flow, polling/slow-down, approval/denial authorization, token exchange hook integration, and verification URI behavior.
- `haveibeenpwned`: default password routes, custom paths/messages, and SHA-1 k-anonymity lookup.
- `email-otp`: send/verify/sign-in/signup/password reset/attempt tracking/storage helpers.
- `mcp`: OAuth/protected-resource metadata, registration, token, refresh, userinfo, JWKS, login-prompt cookie restoration, and helper headers.
- `multi-session`: device sessions, active switching, same-user replacement, active-session authorization, revocation fallback, sign-out cleanup, and forged-cookie safety.
- `phone-number`: OTP, signup/session, update user phone, password sign-in, require verification, reset, attempts, custom validation.
- `one-time-token`: generation/verification, single-use, expiration, expired-session rejection, cookie behavior, storage modes, server-only generation, and `set-ott` headers.
- `jwt`: EdDSA default signing, RS256/PS256/ES256/ES512, JWKS publication/custom path, API-only sign/verify, `set-auth-jwt`, key rotation/grace windows, `kid` selection, expiry, current/previous key verification, and remote JWKS verification.
- `last-login-method`: email, SIWE, social OAuth, generic OAuth, failed callback suppression, subsequent database updates, custom cookie names/prefixes, cross-subdomain/cross-origin attributes, and optional user persistence.
- `oauth-proxy`: callback rewriting, same-origin unwrap, encrypted cross-origin cookie forwarding, timestamp/trusted-callback validation, malformed payload handling, stateless state-cookie package restoration, and DB-less provider callback flow.
- `passkey`: real WebAuthn registration/authentication and management authorization.

High-priority plugin gaps:

- `phone-number`: reset consumes OTP before password/user validation completes.
- `open-api`: snapshot parity missing.
- `siwe`: Ruby lowercases wallet addresses, diverging from upstream checksum casing; duplicate wallet/custom schema/message-shape cases missing.
- `passkey`: option shape, challenge expiration, not-found delete, and allow/exclude transport details are thin.

Plugins implemented in Ruby but partial versus upstream should stay marked `Partial`, not `Ported`, unless the project explicitly accepts the documented gaps. The current partial plugin list is maintained in `.docs/features/plugin-priority-computation.md`.

### Implemented upstream plugin suites still partial

Local Ruby counterparts exist but still have upstream parity gaps:

- `api-key`
- `email-otp`
- `mcp`
- `multi-session`
- `oidc-provider`
- `one-tap`
- `one-time-token`
- `open-api`
- `organization`
- `passkey`
- `phone-number`
- `siwe`
- `sso`
- `scim`
- `oauth-provider`
- `stripe`
- `two-factor`
- `username`
- `expo`

These account for the active plugin parity queue. Stripe and SCIM remain listed here for status accuracy, even when an implementation pass intentionally avoids touching them.

### Upstream suites that are not directly applicable yet

These are real upstream tests, but not direct Ruby server-core obligations unless equivalent Ruby features are added:

- Browser/TS client package tests: `client/client.test.ts`, `client/client-ssr.test.ts`, `client/proxy.test.ts`, `client/url.test.ts`.
- TypeScript inference: `types/types.test.ts`.
- Zod schema generation: `db/to-zod.test.ts`.
- JS adapter implementations: Kysely, Drizzle, Prisma, MongoDB, Bun/node SQLite dialect tests.

Some behavior from those suites should still inform Ruby tests, especially adapter contract semantics.

### Rails adapter

Current coverage is smoke-to-light:

- ActiveRecord create mapping and transaction yield.
- Migration rendering for base tables.
- Route helper mount call.
- Controller helper session lookup from env/cookie.
- Generator creates initializer/migration and skip-existing behavior.
- PostgreSQL integration for generated migration and cross-reading through core SQL adapter, blocked here by sandbox TCP access.

Highest-risk gaps:

- Mounted route path behavior may 404 due to Rails `SCRIPT_NAME`/`PATH_INFO`.
- ActiveRecord adapter does not match core adapter contract for required validation, ID generation, date/boolean coercion, OR connector, select, joins, update/delete/count parity.
- Joins are partial.
- Migration uses `def change` with raw `execute`, which can make rollback non-reversible.
- Generators ignore app/plugin schema, custom fields, and custom model names.
- Controller helpers pass only cookies and may miss bearer/header-based session resolution.

### Docs and plan inconsistencies

The docs are useful but need continuous status synchronization:

- `upstream-parity-matrix.md` now uses `Complete` for completed server-parity plugin rows and `Partial` for rows with remaining upstream gaps.
- OAuth2/social-provider rows are marked `Not started`, but route-level social/account behavior exists and should be `Partial`.
- Rails integration is marked `Not started` in the matrix, but Rails adapter/specs exist and should be `Partial`.
- Some matrix test paths reference files that do not exist, such as standalone `context_test.rb`, `database_hooks_test.rb`, and `secondary_storage_test.rb`.
- Several feature docs still describe pre-Phase-5 state even though route files/tests now exist.

## Recommended Next Work Order

1. Fix security-sensitive session/cookie/password gaps:
   - Long-password hashing. (Resolved 2026-04-27.)
   - Filter `returned: false` fields from cookie cache.
   - Preserve `rememberMe: false` semantics through refresh.
   - Validate GET callback URLs.
   - Preserve password-reset no-enumeration on sender failure.

2. Port social/OAuth and account behavior to upstream parity:
   - PKCE state storage.
   - Trusted provider/account-linking rules.
   - `disableImplicitSignUp` / `disableSignUp` / `requestSignUp`.
   - `newUserCallbackURL`.
   - POST callback redirect-to-GET.
   - Token updates and account cookies.

3. Build a shared Ruby adapter contract suite:
   - Run against Memory, Postgres, MySQL, and ActiveRecord.
   - Include OR connectors, input/returned field enforcement, custom field/model names, joins, update/delete/count, transactions, secondary storage.

4. Fix Rails mount integration:
   - Add request specs for `GET /api/auth/ok` through Rails routes.
   - Decide whether Rails mount should configure core `base_path` to `""` or the router should account for `SCRIPT_NAME`.

5. Add high-value plugin parity tests:
   - JWT rotation.
   - Phone-number reset OTP preservation.
   - OpenAPI snapshot decision.

6. Update docs/matrix:
   - Downgrade overstated `Ported` rows to `Partial`.
   - Mark existing social/OAuth/Rails areas as `Partial`.
   - Remove nonexistent test path references or add the tests.

## Bottom Line

The port is progressing well, but the current local test suite is not yet enough to say "same logic as upstream Better Auth" for all implemented modules. The most important missing coverage is around security and wire-contract edge cases rather than simple happy paths. Upstream has many tests we do not cover yet; some are intentionally out of Ruby scope, some belong to unimplemented plugins, and some reveal real parity gaps in modules that are already implemented.
