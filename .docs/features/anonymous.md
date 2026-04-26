# Feature: Anonymous Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/anonymous/index.ts`, `upstream/packages/better-auth/src/plugins/anonymous/schema.ts`, `upstream/packages/better-auth/src/plugins/anonymous/anon.test.ts`

## Summary

Adds anonymous sign-in, marks temporary users with `isAnonymous`, allows deleting anonymous users, and transfers/cleans up anonymous users when a real account is linked.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.anonymous`.
- Adds `isAnonymous` to the user schema with default `false`.
- Adds `/sign-in/anonymous` and `/delete-anonymous-user`.
- Supports `email_domain_name`, `generate_name`, `generate_random_email`, `disable_delete_anonymous_user`, and `on_link_account`.
- Uses an after hook on sign-in/sign-up/callback-style paths to detect when a request had an anonymous session and a new real session was issued.

## Key Differences

- The Ruby implementation keeps this plugin dependency-free; email validation uses the core route email pattern.
- Ruby options are idiomatic snake_case equivalents of upstream camelCase options.
- Social linking cleanup is implemented through the shared session-cookie/new-session mechanism and is covered through email sign-in tests now; broader social-provider regression coverage remains with the base social route tests.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/anonymous_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/anonymous_test.rb`
