# OAuth Provider Upstream Test Parity Matrix

Target upstream: Better Auth `v1.6.9`, `upstream/packages/oauth-provider/src/**/*.test.ts`.

Status legend:
- Covered: translated to Ruby Minitest or already covered by legacy behavior tests.
- Partial: important upstream behavior is covered, but fine-grained scenario parity is not complete.
- Excluded: intentionally not ported because it is JS/client/browser/resource-package only.

| Upstream file | Status | Ruby coverage / decision |
| --- | --- | --- |
| `authorize.test.ts` | Covered | Issuer URL normalization, unauthenticated login redirect, `prompt=none` `login_required`, PAR `request_uri`, front-channel discard, `iss` success/error/metadata/consent-required coverage, prompt login/create/select/post-login parity. |
| `metadata.test.ts` | Covered with exclusions | OAuth/OIDC core fields, advertised scopes/claims, invalid advertised scopes, remote JWKS, `disable_jwt_plugin`, secondary storage/session constraint. Resource metadata block is excluded until Ruby adds resource-client support. Dynamic JS wrapper tests are not ported because Ruby exposes Rack/API endpoints rather than upstream wrapper functions. |
| `oauth.test.ts` | Covered with exclusions | Provider init, secondary storage, prompt flows, signed continuation, consent re-entry, rate-limit config and token rate-limit enforcement, organization/team post-login selection with consent reference. Generic OAuth client sign-in/fetch/browser redirect ergonomics are excluded. |
| `register.test.ts` | Covered | Empty/missing auth, public/confidential type matrix, unauthenticated coercion to public, invalid confidential grants, metadata stripping/preservation, skip consent rejection, PKCE opt-out rejection, SafeUrl behavior, organization-backed client registration via `client_reference`. |
| `types/zod.test.ts` | Covered by behavior | SafeUrl accept/reject matrix is covered through registration/public behavior, not by porting TS/Zod unit tests verbatim. |
| `oauthClient/endpoints.test.ts` | Covered | Create/get/list/update/delete/rotate, public/prelogin public fields, immutable public/client-secret updates. |
| `oauthClient/endpoints-privileges.test.ts` | Covered with Ruby adaptation | User create/read/list/update/rotate/delete privileges, public read bypass, unauth create, admin create privilege with session. Admin endpoints remain Ruby server-only over Rack, so browser/client admin ergonomics are not ported. |
| `oauthConsent/endpoints.test.ts` | Covered | Get/list/update/delete, reject scope expansion outside client grants, allow narrowed scopes. Upstream tester create-consent helper is covered by real authorization/consent flow. |
| `pkce-optional.test.ts` | Covered | Confidential opt-out, public/offline enforcement, auth/token PKCE mismatch, mismatched challenge, loopback redirect matching, admin-created `require_pkce`. |
| `token.test.ts` | Covered with TS-unit exclusions | Auth-code scope matrix, PKCE state omission, refresh matrix, client credentials matrix, JWT resource tokens, `expires_at`, prefixes, replay cascade, scope expirations, custom token fields, custom ID token claims, loopback redirects, secret storage errors. TypeScript `VerificationValue` schema-unit tests are excluded. |
| `introspect.test.ts` | Covered | Unauthenticated request, opaque/JWT/refresh, no-hint detection, wrong hints, logged-out-user/session-deleted behavior, custom prefixes, upstream active claims. |
| `revoke.test.ts` | Covered | Unauthenticated request, JWT/opaque/refresh, no-hint behavior, wrong hint rejection, custom prefixes. |
| `userinfo.test.ts` | Covered | Missing Authorization header, missing `openid`, headers-only API behavior, opaque/JWT userinfo, sub/profile/email scoping. |
| `logout.test.ts` | Covered | Invalid `id_token_hint`, DCR cannot enable end-session, client without end-session rejected, JSON success, redirect success. |
| `pairwise.test.ts` | Covered | Pairwise secret validation/metadata, registration validation, deterministic client-specific subject, same-sector same-sub, userinfo consistency, introspection pairwise subject, refresh preservation, JWT access token public user id. |
| `utils/query-serialization.test.ts` | Covered | Signed OAuth query preserves repeated params; prompt deletion removes only the selected prompt and preserves arrays. |
| `utils/timestamps.test.ts` | Covered | Epoch-millis strings, invalid values, direct/nested `createdAt`/`created_at`, no fallback to `updatedAt`. |
| `mcp.test.ts` | Excluded | MCP/resource-client package behavior is not part of the Ruby OAuth provider gem yet. |

## Remaining Explicit Exclusions

- `mcp.test.ts`: excluded until the Ruby gem has MCP/resource-client support.
- Resource metadata block in `metadata.test.ts`: excluded until the Ruby gem exposes the resource client package/features.
- Generic OAuth JS client/fetch redirect ergonomics in `oauth.test.ts`: excluded because they validate upstream JS client/browser behavior, not Ruby server behavior.
- TypeScript/Zod unit-only tests: excluded where Ruby behavior is already covered through public registration/token behavior.
