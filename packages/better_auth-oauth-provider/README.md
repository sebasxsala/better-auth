# Better Auth OAuth Provider

External OAuth provider plugin package for `better_auth`.

Upstream ships OAuth provider as `@better-auth/oauth-provider`, separate from core plugin exports. This gem mirrors that boundary for Ruby while keeping Ruby option names snake_case and upstream-compatible HTTP paths and JSON keys.

```ruby
require "better_auth"
require "better_auth/oauth_provider"

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  base_url: "https://auth.example.com/api/auth",
  plugins: [
    BetterAuth::Plugins.oauth_provider(
      scopes: ["openid", "profile", "email", "offline_access"],
      consent_page: "/oauth2/consent",
      allow_dynamic_client_registration: true
    )
  ]
)
```

## Client Registration

Dynamic registration is disabled by default. Enable it explicitly and call it with an authenticated session unless unauthenticated registration is also enabled.

```ruby
client = auth.api.register_o_auth_client(
  headers: {"cookie" => session_cookie},
  body: {
    client_name: "Example Client",
    redirect_uris: ["https://client.example.com/callback"],
    token_endpoint_auth_method: "client_secret_post",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    scope: "openid profile offline_access"
  }
)
```

## Authorization Code Token Exchange

Authorization code clients use S256 PKCE by default.

```ruby
tokens = auth.api.o_auth2_token(
  body: {
    grant_type: "authorization_code",
    code: params[:code],
    redirect_uri: "https://client.example.com/callback",
    client_id: client[:client_id],
    client_secret: client[:client_secret],
    code_verifier: verifier
  }
)
```

When `resource` is present and valid, access tokens are JWTs. Without `resource`, access tokens are opaque and introspectable.

## Routes

| Method | Path | Ruby API method |
| --- | --- | --- |
| `GET` | `/.well-known/oauth-authorization-server` | `auth.api.get_o_auth_server_config` |
| `GET` | `/.well-known/openid-configuration` | `auth.api.get_open_id_config` |
| `POST` | `/oauth2/register` | `auth.api.register_o_auth_client` |
| `POST` | `/oauth2/create-client` | `auth.api.create_o_auth_client` |
| `GET` | `/oauth2/client/:id` | `auth.api.get_o_auth_client` |
| `GET` | `/oauth2/client` | `auth.api.get_o_auth_client_public` |
| `GET` | `/oauth2/public-client-prelogin` | `auth.api.get_o_auth_client_public_prelogin` |
| `GET` | `/oauth2/clients` | `auth.api.list_o_auth_clients` |
| `PATCH` | `/oauth2/client` | `auth.api.update_o_auth_client` |
| `DELETE` | `/oauth2/client` | `auth.api.delete_o_auth_client` |
| `POST` | `/oauth2/client/rotate-secret` | `auth.api.rotate_o_auth_client_secret` |
| `GET` | `/oauth2/authorize` | `auth.api.o_auth2_authorize` |
| `POST` | `/oauth2/continue` | `auth.api.o_auth2_continue` |
| `POST` | `/oauth2/consent` | `auth.api.o_auth2_consent` |
| `GET` | `/oauth2/consents` | `auth.api.list_o_auth_consents` |
| `GET` | `/oauth2/consent` | `auth.api.get_o_auth_consent` |
| `PATCH` | `/oauth2/consent` | `auth.api.update_o_auth_consent` |
| `DELETE` | `/oauth2/consent` | `auth.api.delete_o_auth_consent` |
| `POST` | `/oauth2/token` | `auth.api.o_auth2_token` |
| `POST` | `/oauth2/introspect` | `auth.api.o_auth2_introspect` |
| `POST` | `/oauth2/revoke` | `auth.api.o_auth2_revoke` |
| `GET` | `/oauth2/userinfo` | `auth.api.o_auth2_user_info` |
| `GET`, `POST` | `/oauth2/end-session` | `auth.api.o_auth2_end_session` |

## Options

Common options accepted by `BetterAuth::Plugins.oauth_provider`:

- `login_page`
- `consent_page`
- `scopes`
- `claims`
- `grant_types`
- `allow_dynamic_client_registration`
- `allow_unauthenticated_client_registration`
- `client_registration_default_scopes`
- `client_registration_allowed_scopes`
- `store_client_secret`
- `prefix`
- `refresh_token_expires_in`
- `advertised_metadata`
- `valid_audiences`
- `custom_token_response_fields`
- `custom_access_token_claims`
- `custom_user_info_claims`
- `pairwise_secret`
- `signup`
- `select_account`
- `post_login`
- `client_privileges`
- `rate_limit`
- `jwks_uri`
- `disable_jwt_plugin`
- `store`

OIDC provider remains a core `better_auth` plugin because upstream still exposes it from `better-auth/plugins`. OAuth provider is the newer standalone provider package.
