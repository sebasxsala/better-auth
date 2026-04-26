# Feature: Magic Link Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/magic-link/index.ts`, `upstream/packages/better-auth/src/plugins/magic-link/magic-link.test.ts`, `upstream/packages/better-auth/src/plugins/magic-link/utils.ts`

## Summary

Adds email magic-link sign-in, magic-link verification, new-user sign-up through magic links, existing-user email verification, redirect/error handling, and configurable token storage.
The demo-level Rack flow is covered end to end through `/sign-in/magic-link` and `/magic-link/verify`.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.magic_link`.
- Adds `/sign-in/magic-link` and `/magic-link/verify`.
- Stores magic-link tokens through the core verification table.
- Supports `expires_in`, `send_magic_link`, `disable_sign_up`, `generate_token`, `store_token: "plain"`, `store_token: "hashed"`, and custom hasher storage.
- Uses core origin/trusted-origin checks for verify callback URLs.

## Key Differences

- The Ruby implementation keeps token hashing dependency-free using `BetterAuth::Crypto.sha256(..., encoding: :base64url)`, matching upstream's SHA-256/base64url storage shape.
- Ruby options use snake_case equivalents of upstream camelCase options.
- Direct API verification returns JSON when no callback URL is supplied, and Rack/API response mode returns redirects for callback and error flows.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/magic_link_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/magic_link_test.rb`
