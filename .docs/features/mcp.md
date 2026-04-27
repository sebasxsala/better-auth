# Feature: MCP Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/mcp/index.ts`, `upstream/packages/better-auth/src/plugins/mcp/authorize.ts`, `upstream/packages/better-auth/src/plugins/mcp/mcp.test.ts`, `upstream/packages/oauth-provider/src/mcp.ts`, `upstream/packages/oauth-provider/src/mcp.test.ts`

## Summary

Adds MCP OAuth metadata, protected-resource metadata, dynamic public client registration, authorization-code flow with PKCE, token refresh, userinfo, JWKS route, and Rack helper behavior for unauthenticated MCP resource requests.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.mcp`.
- Adds `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/mcp/authorize`, `/mcp/token`, `/mcp/userinfo`, `/mcp/register`, and `/mcp/jwks`.
- Reuses OIDC/OAuth schema entries and shared protocol helpers.
- Adds `BetterAuth::Plugins::MCP.with_mcp_auth` to return a `401` with the expected `WWW-Authenticate` bearer metadata challenge when a request has no bearer token.
- Persists unauthenticated authorization queries in an `oidc_login_prompt` signed cookie and resumes the MCP authorization redirect after email sign-in.

## Key Differences

- Ruby options use snake_case equivalents of upstream camelCase.
- `/mcp/jwks` publishes public signing keys from the shared `jwks` store used by the JWT plugin.
- Consent UI/client package helpers remain outside the Ruby server surface; the server redirect/token/helper behavior is covered.

## Testing

```bash
cd packages/better_auth
rbenv exec ruby -Ilib -Itest test/better_auth/plugins/mcp_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/mcp_test.rb`
