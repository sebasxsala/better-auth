# Feature: MCP Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/mcp/index.ts`, `upstream/packages/better-auth/src/plugins/mcp/authorize.ts`, `upstream/packages/better-auth/src/plugins/mcp/mcp.test.ts`, `upstream/packages/oauth-provider/src/mcp.ts`, `upstream/packages/oauth-provider/src/mcp.test.ts`

## Summary

Adds MCP OAuth metadata, protected-resource metadata, dynamic public client registration, authorization-code flow with PKCE, token refresh, userinfo, JWKS route, and Rack helper behavior for unauthenticated MCP resource requests.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.mcp`.
- Adds `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/mcp/authorize`, `/mcp/token`, `/mcp/userinfo`, `/mcp/register`, and `/mcp/jwks`.
- Reuses OIDC/OAuth schema entries and shared protocol helpers.
- Adds `BetterAuth::Plugins::MCP.with_mcp_auth` to return a `401` with the expected `WWW-Authenticate` bearer metadata challenge when a request has no bearer token.

## Key Differences

- Ruby options use snake_case equivalents of upstream camelCase.
- The current JWKS endpoint returns an empty key set unless a later JWT/OIDC integration wires MCP-specific key publication.
- Login redirect persistence is simplified to query-preserving redirects to the configured `login_page`; full upstream cookie persistence for login prompt restoration remains future polish.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/mcp_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/mcp_test.rb`
