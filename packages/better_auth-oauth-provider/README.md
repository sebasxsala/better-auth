# Better Auth OAuth Provider

External OAuth provider plugin package for `better_auth`.

Upstream ships OAuth provider as `@better-auth/oauth-provider`, separate from core plugin exports. This gem mirrors that boundary for Ruby.

```ruby
require "better_auth"
require "better_auth/oauth_provider"

BetterAuth.auth(
  plugins: [
    BetterAuth::Plugins.oauth_provider
  ]
)
```

OIDC provider remains a core `better_auth` plugin because upstream still exposes it from `better-auth/plugins`. OAuth provider is the newer standalone provider package.
