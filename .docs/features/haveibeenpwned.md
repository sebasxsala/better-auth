# Feature: Have I Been Pwned Plugin

Status: Complete for Ruby server parity.

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/haveibeenpwned/index.ts`, `upstream/packages/better-auth/src/plugins/haveibeenpwned/haveibeenpwned.test.ts`

## Summary

Blocks compromised passwords on configured password routes using the Have I Been Pwned k-anonymity range API.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.have_i_been_pwned`.
- Checks `/sign-up/email`, `/change-password`, and `/reset-password` by default.
- Supports custom `paths`, `custom_password_compromised_message`, and injectable `range_lookup` for tests/apps.
- Hashes candidate passwords with SHA-1 uppercase, sends only the first five hash characters to the range lookup, and compares suffixes case-insensitively.
- Raises `PASSWORD_COMPROMISED` before password hashes are persisted.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/have_i_been_pwned_test.rb
```
