# Feature: Dub Plugin

Status: Complete for Ruby server parity with the documented upstream `@dub/better-auth` server behavior.

**Upstream Reference:** `upstream/docs/content/docs/plugins/dub.mdx`

## Summary

Adds `BetterAuth::Plugins.dub` for Dub lead tracking and optional Dub OAuth account linking.

## Ruby Adaptation

- Implemented in the core gem for now because the server surface is small and does not require the Dub gem.
- Uses an injected `dub_client` object; applications may pass the official Dub Ruby SDK or any compatible object that responds to `track.lead`.
- Tracks signup leads from the `dub_id` cookie after user creation, then expires the cookie.
- Adds `/dub/link` when Dub OAuth is configured and reuses the generic OAuth callback route for `/oauth2/callback/:providerId`.
- Preserves upstream-style option names while accepting Ruby-style snake_case options.

## Packaging Decision

Keep this in core unless it grows a hard runtime dependency, schema tables, or a substantially larger route surface. If that happens, extract it to a dedicated `better_auth-dub` gem the same way passkey, API key, SSO, SCIM, OAuth provider, and Stripe are packaged.

## Covered Behavior

- Signup lead tracking from `dub_id`.
- Custom event names and custom lead tracking callbacks.
- Non-blocking default tracking errors.
- Compatibility with the official Ruby SDK request wrapper shape.
- Optional OAuth link endpoint and OAuth callback registration.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/dub_test.rb
```
