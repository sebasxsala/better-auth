# OAuth Provider Future Work: Resource Client And MCP

## Context

The Ruby `better_auth-oauth-provider` package now covers the applicable upstream OAuth provider server behavior, including organization/team integration through the Ruby organization plugin.

The remaining upstream OAuth provider tests that are not ported are not ordinary authorization-server behavior. They cover package-adjacent client/resource-server features:

- `oauthProviderResourceClient` from `upstream/packages/oauth-provider/src/client-resource.ts`
- OAuth protected resource metadata helpers from the upstream resource client
- `mcp.test.ts`, which combines the resource client, MCP SDK server/client transports, protected-resource challenge headers, and OAuth token verification
- Browser/JS client ergonomics that validate upstream JavaScript client packages rather than Ruby server behavior

## Current Ruby Support

Ruby has a separate core MCP plugin documented in `.docs/features/mcp.md` and `docs/content/docs/plugins/mcp.mdx`. That plugin exposes MCP OAuth endpoints and a Rack helper for MCP-protected resources.

The OAuth provider gem itself does not currently expose a resource-client API equivalent to upstream `oauthProviderResourceClient`.

## Future API To Design

If we want full upstream resource-client/MCP parity inside or beside `better_auth-oauth-provider`, design a public Ruby API for resource servers. Possible shape:

- A Rack helper/middleware that validates bearer access tokens for protected APIs.
- Local JWT verification using JWKS URL and expected issuer/audience.
- Optional remote introspection with confidential client credentials.
- Generation of OAuth protected resource metadata responses.
- `WWW-Authenticate` bearer challenges with `resource_metadata` parameters for invalid/missing tokens.
- Integration hooks for Ruby MCP servers that want to use the OAuth provider as their authorization server.

## Suggested Next Step

Create a separate implementation plan once the desired Ruby API boundary is chosen:

- Option A: add resource-client helpers to `better_auth-oauth-provider`.
- Option B: add a new package, for example `better_auth-oauth-provider-resource`.
- Option C: keep this in core MCP only and document that OAuth provider does not own resource-server helpers.
