# Feature: One Tap Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/one-tap/index.ts`, `upstream/packages/better-auth/src/plugins/one-tap/client.ts`

## Summary

Adds Google One Tap sign-in through `POST /one-tap/callback`.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.one_tap`.
- Adds `/one-tap/callback`.
- Verifies the Google ID token, creates a Google OAuth account for new users, reuses existing Google accounts, links existing users when Google is trusted or the token email is verified, creates a session, and sets the session cookie.
- Supports upstream `disableSignup` and `clientId` as Ruby `disable_signup` and `client_id`.
- Supports a Ruby-specific `verify_id_token` callable for tests and applications that need custom Google token verification.
- Rejects missing-email, invalid-token, disabled-signup, disabled account-linking, and untrusted unverified linking cases with upstream-compatible responses.

## Key Differences

- Upstream verifies Google tokens with `jose` and Google's remote JWKS. Ruby uses the existing `jwt` runtime dependency and stdlib `Net::HTTP` to fetch Google's JWKS by default.
- The test suite injects `verify_id_token` to avoid network-dependent tests while preserving the endpoint contract.
- The upstream client package handles browser Google One Tap and FedCM prompts. The Ruby core port exposes the server callback only.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/one_tap_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/one_tap_test.rb`
