# Plugin Priority Computation

Last updated: 2026-04-27

## Status Rule

`Complete` / `[x] Supported` means every server-relevant upstream runtime behavior has Ruby tests and documented Ruby adaptations are intentional. TypeScript inference, browser client packages, and native mobile client storage are out of scope only when the docs explicitly name the Ruby server surface.

## Inputs Checked

- `README.md` plugin table
- `.docs/features/upstream-parity-matrix.md`
- `.docs/features/*.md`
- `packages/better_auth/lib/better_auth/plugins/*.rb`
- `packages/better_auth/test/better_auth/plugins/*_test.rb`
- upstream plugin tests under `upstream/packages/better-auth/src/plugins/`, `upstream/packages/passkey/src/`, `upstream/packages/oauth-provider/src/`, `upstream/packages/sso/src/`, `upstream/packages/scim/src/`, `upstream/packages/stripe/test/`, and `upstream/packages/expo/test/`

## Promoted To Complete

These plugins are complete for Ruby server parity and should not appear in the partial queue:

- Access control
- Additional fields
- Admin
- Anonymous
- API key
- Bearer
- Captcha
- Custom session
- Device authorization
- Email OTP
- Expo server integration
- Generic OAuth
- Have I Been Pwned
- Magic link
- MCP
- Multi-session
- One tap
- One-time token
- Phone number
- Two-factor
- Username

## Still Partial

These plugins still have documented upstream parity gaps:

| Plugin | Remaining gap summary |
| --- | --- |
| JWT/JWKS | Broader JOSE algorithm decisions, remote signing matrix, and remote JWKS verification parity. |
| Last login method | SIWE, generic OAuth, social callback, custom prefix/cross-origin cookie, and database update coverage. |
| OAuth proxy | Exact stateless state-cookie package restoration and DB-less provider flow coverage. |
| OAuth provider | Organization reference, logout, encrypted client-secret variants, rate-limit matrices, and broader client/consent lifecycle coverage. |
| OIDC provider | Consent UI behavior decision, prompt/max-age matrix, JWT plugin algorithm negotiation, encrypted client-secret variants, and full dynamic-client lifecycle. |
| OpenAPI | Snapshot-style schema parity or a documented Ruby schema contract with tests. |
| Organization | Exhaustive route/access-control matrix, member/invitation/team flows, hooks, additional fields, SQL/Rails plugin schema migrations, and dynamic-role edge cases. |
| Passkey | Option-shape parity, challenge expiration, delete not-found behavior, allow/exclude transport details, and browser-client docs/API-surface decision. |
| SIWE | Checksum-casing decision, duplicate wallet behavior, custom schema/message shapes, and exact upstream response parity. |
| SSO | SAML XML signature/assertion/encryption/metadata parsing decisions, OIDC discovery HTTP matrix, and advanced organization provisioning policies. |
| SCIM | Broader RFC filter/PATCH matrix, organization enforcement, token lifecycle edge cases, and mapping customization parity. |
| Stripe | Complete billing event matrix, plan/seat/trial abuse cases, webhook ordering, organization mode edge cases, and subscription state transitions. |

## Priority Order

1. Security/session-sensitive: JWT/JWKS.
2. Authentication flows: SIWE, Passkey, Last login method.
3. OAuth/protocol: Generic OAuth, OAuth proxy, OAuth provider, OIDC provider.
4. Management/enterprise: Organization, SSO, SCIM, Stripe.
5. Tooling/integration docs: OpenAPI.
