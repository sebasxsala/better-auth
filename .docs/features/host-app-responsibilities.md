# Host App Responsibilities

Better Auth Ruby validates auth requests, but the host application still owns
the browser and deployment policies around the mounted auth app.

## Origin Validation vs Browser CORS

Better Auth uses `trusted_origins` for origin and callback URL checks where the
core router requires them. This is not the same thing as browser CORS.

Browsers enforce CORS through `Access-Control-*` request and response headers.
If a frontend calls Better Auth from another origin, configure Rack middleware
or reverse-proxy rules in the host app. Adapter gems should not emit a global
CORS policy because the allowed origins, credential mode, preflight behavior,
and proxy topology are application deployment concerns.

## CSRF

Framework adapters do not replace SameSite cookie settings or framework CSRF
protection for non-API browser flows. Rails, Hanami, Sinatra, and other Rack
apps should keep their normal CSRF defenses for their own HTML forms and
controller actions.

Sinatra apps mount Better Auth as Rack middleware through the adapter. Custom
Sinatra routes that read Better Auth sessions should still apply the app's own
CSRF and request validation policy where those routes mutate browser state.

## `trusted_origins` Deployment

Upstream Better Auth builds trusted origins from the resolved app origin,
explicit `trustedOrigins`, dynamic resolvers, plugin-provided origins, and
environment configuration. Ruby follows the same deployment model.

An empty or unset list should not be treated as a universal "deny every browser
origin" switch unless the core configuration contract explicitly documents that
merge behavior for the deployed app. Configure concrete origins per environment
instead of relying on adapter-only empty-list behavior.

See the core README's `trusted_origins` guidance in
[`packages/better_auth/README.md`](../../packages/better_auth/README.md#trusted-origins).
