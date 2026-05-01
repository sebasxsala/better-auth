# Concepts Docs Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `docs/content/docs/concepts/` to upstream Better Auth `v1.6.9` content parity, adapted to Ruby examples, while verifying every documented example is implemented or explicitly excluded.

**Architecture:** Treat `upstream/docs/content/docs/concepts/` as the content source of truth and `upstream/packages/better-auth/src/` as the behavior source of truth. For each concept page, audit upstream examples against Ruby core, Rails adapter, and existing tests before rewriting the local docs. Do not document unsupported behavior as available; either implement and test it first, or omit it with a Ruby-specific explanation.

**Tech Stack:** Ruby 3.2+, BetterAuth core gem, Rails adapter, MDX docs, Minitest, RSpec for Rails adapter, upstream Better Auth docs/source/tests.

---

## Scope

Concept pages to audit and rewrite:

| Upstream source | Local target | Initial action |
| --- | --- | --- |
| `upstream/docs/content/docs/concepts/api.mdx` | `docs/content/docs/concepts/api.mdx` | Adapt server-side endpoint calls, response headers, Rack responses, and `BetterAuth::APIError` handling. |
| `upstream/docs/content/docs/concepts/cli.mdx` | `docs/content/docs/concepts/cli.mdx` | Replace package-install commands with Ruby/Rails generator and gem development commands. |
| `upstream/docs/content/docs/concepts/client.mdx` | `docs/content/docs/concepts/client.mdx` | Replace TypeScript client/hooks with HTTP examples, server-side Ruby calls, Rack mounting, and Rails helpers. |
| `upstream/docs/content/docs/concepts/cookies.mdx` | `docs/content/docs/concepts/cookies.mdx` | Adapt cookie prefix, custom cookies, secure cookies, cross-subdomain cookies, Safari guidance, and proxy guidance. |
| `upstream/docs/content/docs/concepts/database.mdx` | `docs/content/docs/concepts/database.mdx` | Adapt adapters, migrations, secondary storage, core schema, custom tables, custom fields, ID generation, database hooks, plugin schema. |
| `upstream/docs/content/docs/concepts/email.mdx` | `docs/content/docs/concepts/email.mdx` | Adapt email verification, `send_on_sign_up`, `send_on_sign_in`, manual send, verify email, auto sign-in, callbacks, duplicate signup callback, password reset. |
| `upstream/docs/content/docs/concepts/hooks.mdx` | `docs/content/docs/concepts/hooks.mdx` | Adapt before/after hooks, endpoint context, response helpers, cookies, errors, context fields, background execution, reusable hooks where Ruby supports them. |
| `upstream/docs/content/docs/concepts/oauth.mdx` | `docs/content/docs/concepts/oauth.mdx` | Adapt providers, sign-in, linking, access token, account info, additional scopes/data, provider options, profile mapping, refresh token behavior. |
| `upstream/docs/content/docs/concepts/plugins.mdx` | `docs/content/docs/concepts/plugins.mdx` | Adapt server plugins, endpoints, schema, hooks, middleware, request/response handlers, rate limits, trusted origins, helper equivalents. |
| `upstream/docs/content/docs/concepts/rate-limit.mdx` | `docs/content/docs/concepts/rate-limit.mdx` | Adapt defaults, IP handling, IPv6/subnet support if present, windows, custom rules, storage, errors, schema. |
| `upstream/docs/content/docs/concepts/session-management.mdx` | `docs/content/docs/concepts/session-management.mdx` | Adapt session expiry, refresh, freshness, get/list/revoke/update sessions, password-change revocation, cookie cache, secondary storage, stateless sessions, custom response. |
| `upstream/docs/content/docs/concepts/users-accounts.mdx` | `docs/content/docs/concepts/users-accounts.mdx` | Adapt update user, change email, change password, set/verify password, delete user, delete verification, callbacks, account listing/linking/unlinking, token encryption. |
| `upstream/docs/content/docs/concepts/typescript.mdx` | `docs/content/docs/concepts/typescript.mdx` | Remove from concepts or move Ruby-port notes elsewhere; do not keep a TypeScript concept page in Ruby docs. |

Out of scope for this plan:

- Plugin-specific docs under `docs/content/docs/plugins/`.
- Authentication provider pages under `docs/content/docs/authentication/`.
- Implementing large missing features without adding a dedicated follow-up plan when the missing work is broader than a concept example.

## Initial Findings

- Session revocation APIs exist in Ruby core: `list_sessions`, `revoke_session`, `revoke_other_sessions`, and `revoke_sessions` are defined in `packages/better_auth/lib/better_auth/routes/session.rb` and tested in `packages/better_auth/test/better_auth/routes/session_routes_test.rb`.
- Email verification send-on-sign-up exists: `send_sign_up_verification_email` uses `email_verification[:send_on_sign_up]` and falls back to `email_and_password[:require_email_verification]` in `packages/better_auth/lib/better_auth/routes/sign_up.rb`.
- Email verification send-on-sign-in exists: `send_sign_in_verification_email` checks `email_verification[:send_on_sign_in]` in `packages/better_auth/lib/better_auth/routes/sign_in.rb`.
- Email verification callbacks exist: `before_email_verification`, `on_email_verification`, `after_email_verification`, and `auto_sign_in_after_verification` are wired in `packages/better_auth/lib/better_auth/routes/email_verification.rb`.
- Duplicate sign-up callback exists as `email_and_password[:on_existing_user_sign_up]` and is tested in `packages/better_auth/test/better_auth/routes/sign_up_test.rb`.
- Upstream `auth-client.ts` `onError` examples are TypeScript client behavior. Ruby docs should translate those to `rescue BetterAuth::APIError` for server-side Ruby and HTTP status handling for curl/Rack examples.
- The local `docs/content/docs/concepts/typescript.mdx` currently contains Ruby port notes. That content should be moved to a Ruby-specific page or folded into `basic-usage`, `api`, and Rails integration docs before removing the TypeScript concept page.

## Audit Rules

- [ ] For every upstream heading, mark one of: `Ruby docs`, `Ruby docs with adaptation`, `Implemented first`, `Ruby exclusion`.
- [ ] For every upstream code block that becomes Ruby, point to an existing method/configuration path and at least one existing or new test.
- [ ] For every upstream TypeScript-only client hook, atom, type inference, package-install, or generated client section, remove it or replace it with a Ruby/Rack/Rails equivalent.
- [ ] Before rewriting a concept file, inspect the matching upstream implementation and tests under `upstream/packages/better-auth/src/`.
- [ ] If an example is useful but not implemented in Ruby, implement it with tests before documenting it.
- [ ] If an example is intentionally not Ruby-applicable, document the exclusion only when users would otherwise expect it from upstream.

## Tasks

### Task 1: Build The Concept Audit Matrix

**Files:**
- Create: `.docs/features/concepts-docs-upstream-parity.md`
- Modify: `.docs/plans/2026-04-30-concepts-docs-upstream-parity.md`

- [x] Extract upstream headings and code fences:

```bash
ruby -e 'ARGV.each do |f|; puts "## #{f}"; File.readlines(f).each_with_index { |line,i| puts "#{i + 1}: #{line.strip}" if line =~ /^(#+\s|```)/ }; end' upstream/docs/content/docs/concepts/*.mdx
```

- [x] Extract local headings and code fences:

```bash
ruby -e 'ARGV.each do |f|; puts "## #{f}"; File.readlines(f).each_with_index { |line,i| puts "#{i + 1}: #{line.strip}" if line =~ /^(#+\s|```)/ }; end' docs/content/docs/concepts/*.mdx
```

- [x] Create `.docs/features/concepts-docs-upstream-parity.md` with one section per concept and this table shape:

```markdown
| Upstream section | Ruby status | Implementation/test reference | Docs action |
| --- | --- | --- | --- |
| Email Verification > During Sign-up | Implemented | `routes/sign_up.rb`, `routes/sign_up_test.rb` | Rewrite with `send_on_sign_up` Ruby example. |
```

- [x] Update this plan with any broad missing behavior found during matrix creation.

  Initial broad gap: upstream documents IPv6 subnet rate limiting. Ruby rate limiting currently keys by the full client IP plus path, so the matrix marks IPv6 subnet behavior as `Implemented first` unless a later audit finds existing equivalent support.

### Task 2: Audit Core API, Client, CLI, And Cookies Concepts

**Files:**
- Modify: `.docs/features/concepts-docs-upstream-parity.md`
- Later docs targets: `docs/content/docs/concepts/api.mdx`, `cli.mdx`, `client.mdx`, `cookies.mdx`
- Inspect: `packages/better_auth/lib/better_auth/api.rb`
- Inspect: `packages/better_auth/lib/better_auth/router.rb`
- Inspect: `packages/better_auth/lib/better_auth/cookies.rb`
- Inspect: `packages/better_auth/lib/better_auth/configuration.rb`
- Inspect: `packages/better_auth-rails/lib/better_auth/rails/controller_helpers.rb`
- Inspect: `packages/better_auth-rails/lib/generators/better_auth/install/install_generator.rb`
- Inspect: `packages/better_auth-rails/lib/generators/better_auth/migration/migration_generator.rb`

- [x] Verify direct server-side API call examples map to `auth.api.<endpoint>` with `body:`, `headers:`, `query:`, and `as_response: true`.
- [x] Verify response header and Rack response examples are covered by `packages/better_auth/test/better_auth/api_test.rb` and route tests.
- [x] Verify `BetterAuth::APIError` status/code/message examples against existing error behavior.
- [x] Verify Rails helper examples against `packages/better_auth-rails/spec/better_auth/rails/controller_helpers_spec.rb`.
- [x] Verify Rails install and migration commands against Rails generator specs.
- [x] Verify cookie prefix, secure cookie, custom cookie, cross-subdomain, cookie cache, and account cookie examples against `cookies_test.rb`, `auth_context_upstream_parity_test.rb`, and configuration tests.
- [x] Mark TypeScript-only client hooks, atoms, generated clients, and hook rerender options as Ruby exclusions or replace with HTTP/Rails helper equivalents.

### Task 3: Audit Session, Email, And Users/Accounts Concepts

**Files:**
- Modify: `.docs/features/concepts-docs-upstream-parity.md`
- Later docs targets: `docs/content/docs/concepts/session-management.mdx`, `email.mdx`, `users-accounts.mdx`
- Inspect: `packages/better_auth/lib/better_auth/routes/session.rb`
- Inspect: `packages/better_auth/lib/better_auth/routes/sign_up.rb`
- Inspect: `packages/better_auth/lib/better_auth/routes/sign_in.rb`
- Inspect: `packages/better_auth/lib/better_auth/routes/email_verification.rb`
- Inspect: `packages/better_auth/lib/better_auth/routes/password.rb`
- Inspect: `packages/better_auth/lib/better_auth/routes/user.rb`
- Inspect: `packages/better_auth/lib/better_auth/routes/account.rb`
- Upstream inspect: `upstream/packages/better-auth/src/api/routes/sign-up.ts`
- Upstream inspect: `upstream/packages/better-auth/src/api/routes/sign-in.ts`
- Upstream inspect: `upstream/packages/better-auth/src/api/routes/account.ts`
- Upstream inspect: `upstream/packages/better-auth/src/api/routes/password.ts`

- [x] Verify session expiration, refresh disabling, refresh deferral, freshness, and sensitive endpoint behavior against `session_test.rb`.
- [x] Verify `get_session`, `list_sessions`, `revoke_session`, `revoke_other_sessions`, `revoke_sessions`, and `update_session` against `session_routes_test.rb`.
- [x] Verify password-change session revocation against `routes/user.rb` and `user_routes_test.rb`.
- [x] Verify cookie cache strategies, stateless sessions, secondary storage, and session custom fields against `session_test.rb`, `configuration_test.rb`, `schema_test.rb`, and `routes/session_routes_test.rb`.
- [x] Verify `send_verification_email`, `send_on_sign_up`, `send_on_sign_in`, `verify_email`, `auto_sign_in_after_verification`, `before_email_verification`, `on_email_verification`, `after_email_verification`, and `on_existing_user_sign_up`.
- [x] Verify password reset email, reset token callback, `on_password_reset`, and `revoke_sessions_on_password_reset`.
- [x] Verify change email, update email with verification, update without verification, current-email confirmation, delete user verification email, delete callbacks, and delete authentication requirements.

  Implemented missing upstream parity for `user.change_email.send_change_email_confirmation` and `requestType`-aware `verify_email` handling.

- [x] Translate upstream `authClient.*` examples to Ruby `auth.api.*` examples or HTTP examples.

### Task 4: Audit Database, Hooks, Rate Limit, Plugins, And OAuth Concepts

**Files:**
- Modify: `.docs/features/concepts-docs-upstream-parity.md`
- Later docs targets: `docs/content/docs/concepts/database.mdx`, `hooks.mdx`, `rate-limit.mdx`, `plugins.mdx`, `oauth.mdx`
- Inspect: `packages/better_auth/lib/better_auth/schema.rb`
- Inspect: `packages/better_auth/lib/better_auth/schema/sql.rb`
- Inspect: `packages/better_auth/lib/better_auth/adapters/internal_adapter.rb`
- Inspect: `packages/better_auth/lib/better_auth/database_hooks.rb`
- Inspect: `packages/better_auth/lib/better_auth/rate_limiter.rb`
- Inspect: `packages/better_auth/lib/better_auth/plugin.rb`
- Inspect: `packages/better_auth/lib/better_auth/plugin_registry.rb`
- Inspect: `packages/better_auth/lib/better_auth/routes/social.rb`
- Inspect: `packages/better_auth/lib/better_auth/routes/account.rb`

- [x] Verify database adapters, Rails ActiveRecord adapter, core tables, custom table names, custom field names, additional fields, ID generation, plugin schema, and migration generation.
- [x] Verify secondary storage examples against `adapters/internal_adapter_test.rb` and `routes/session_routes_test.rb`.
- [x] Verify database hooks before/after/error/abort behavior against `database_hooks.rb`, `internal_adapter_test.rb`, and route tests.
- [x] Verify API hooks before/after, context mutation, response helpers, cookies, and error behavior against `router_test.rb`, `endpoint_test.rb`, and `auth_context_upstream_parity_test.rb`.
- [x] Verify rate limit defaults, custom rules, path-specific disabling, secondary storage, custom storage, database storage, retry headers, and IP extraction.
- [x] Verify plugin examples for endpoints, schema, hooks, middleware, request/response handlers, rate limits, plugin defaults, and trusted origins.
- [x] Verify OAuth provider configuration, social sign-in, account linking, ID token sign-in, access token refresh, account info, token encryption, scopes, state data, profile mapping, and providers without email.
- [x] Mark upstream helper APIs with no Ruby equivalent, such as TypeScript client plugin atoms or framework hooks, as exclusions.

  Implemented missing upstream parity for rate-limit `storage: "database"` runtime behavior. The schema already existed; `RateLimiter` now reads/writes the `rateLimit` table and stores `lastRequest` in upstream-compatible milliseconds.

### Task 5: Implement Missing Behavior Before Documenting It

**Files:**
- Modify only files identified by Tasks 2-4.
- Core code changes must stay under `packages/better_auth/`.
- Rails adapter code changes must stay under `packages/better_auth-rails/`.
- Tests must be added beside existing related tests.

- [x] For each missing behavior found in the audit matrix, add a failing Ruby test modeled on the upstream test title.
- [x] Implement the smallest Ruby behavior needed to match upstream semantics.
- [x] Update `.docs/features/concepts-docs-upstream-parity.md` from `Missing` to `Implemented` with exact test references.
- [ ] If missing behavior is larger than a concept-doc support fix, create a separate `.docs/plans/YYYY-MM-DD-short-name.md` plan and keep the concept docs from claiming support until that plan lands.

Focused verification commands:

```bash
cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/routes/session_routes_test.rb
cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/routes/sign_up_test.rb
cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/routes/sign_in_test.rb
cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/routes/email_verification_test.rb
cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/routes/user_routes_test.rb
cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/routes/account_test.rb
cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/router_test.rb
cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/cookies_test.rb
cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/schema_test.rb
cd packages/better_auth && rbenv exec bundle exec ruby -Itest test/better_auth/adapters/internal_adapter_test.rb
```

Rails verification commands:

```bash
cd packages/better_auth-rails && rbenv exec bundle exec rspec spec/generators/better_auth/install_generator_spec.rb
cd packages/better_auth-rails && rbenv exec bundle exec rspec spec/generators/better_auth/migration_generator_spec.rb
cd packages/better_auth-rails && rbenv exec bundle exec rspec spec/better_auth/rails/controller_helpers_spec.rb
```

### Task 6: Rewrite Concept Docs From Upstream With Ruby Adaptation

**Files:**
- Modify: `docs/content/docs/concepts/api.mdx`
- Modify: `docs/content/docs/concepts/cli.mdx`
- Modify: `docs/content/docs/concepts/client.mdx`
- Modify: `docs/content/docs/concepts/cookies.mdx`
- Modify: `docs/content/docs/concepts/database.mdx`
- Modify: `docs/content/docs/concepts/email.mdx`
- Modify: `docs/content/docs/concepts/hooks.mdx`
- Modify: `docs/content/docs/concepts/oauth.mdx`
- Modify: `docs/content/docs/concepts/plugins.mdx`
- Modify: `docs/content/docs/concepts/rate-limit.mdx`
- Modify: `docs/content/docs/concepts/session-management.mdx`
- Modify: `docs/content/docs/concepts/users-accounts.mdx`
- Delete or move: `docs/content/docs/concepts/typescript.mdx`

- [x] Preserve upstream section order when the section applies to Ruby.
- [x] Replace TypeScript snippets with Ruby snippets using `BetterAuth.auth`, `auth.api.*`, Rack, Rails initializers, Rails routes, or Rails controller helpers.
- [x] Use `snake_case` Ruby option names and mention camelCase request-body compatibility only where it helps users migrating from upstream.
- [x] Remove TypeScript-specific sections: type inference, `tsconfig`, React/Vue/Svelte/Solid hooks, client atoms, generated TypeScript client examples, and package-install tabs.
- [x] Keep concise Ruby exclusions for upstream sections that users may look for, especially browser hooks and TypeScript type inference.
- [x] Do not add unsupported examples to docs.

### Task 7: Final Docs And Test Verification

**Files:**
- Modify: `.docs/features/concepts-docs-upstream-parity.md`
- Modify: `.docs/plans/2026-04-30-concepts-docs-upstream-parity.md`

- [x] Run focused tests for any implementation changed in Task 5.
- [x] Run core full test suite:

```bash
cd packages/better_auth && rbenv exec bundle exec rake test
```

- [x] Run core lint:

```bash
cd packages/better_auth && rbenv exec bundle exec standardrb
```

- [x] Run Rails adapter specs if Rails docs or adapter behavior changed:

```bash
cd packages/better_auth-rails && rbenv exec bundle exec rspec
```

- [x] Search rewritten concept docs for TypeScript leftovers:

```bash
rg -n 'typescript|TypeScript|tsconfig|auth-client.ts|InferSession|InferUser|createAuthClient|useSession|React|Vue|Svelte|Solid|```ts|```typescript' docs/content/docs/concepts
```

- [x] Search rewritten concept docs for unsupported promises:

```bash
rg -n 'not supported|unsupported|coming soon|planned|not yet' docs/content/docs/concepts
```

- [x] Confirm every row in `.docs/features/concepts-docs-upstream-parity.md` is marked `Ruby docs`, `Ruby docs with adaptation`, `Implemented first`, or `Ruby exclusion`.
- [x] Mark completed plan checkboxes as work lands.

## Acceptance Criteria

- Each local concept page tracks upstream content structure where Ruby-applicable.
- Every Ruby example in concept docs maps to implemented behavior and a test reference in the audit matrix.
- Session revocation, email verification send-on-sign-up, email verification send-on-sign-in, email verification callbacks, password reset, and user/account operations are documented only after verification.
- TypeScript-specific concept documentation is removed from Ruby concepts or moved into a Ruby-port note outside the concepts list.
- Focused tests pass for every changed implementation area.
- `rbenv exec bundle exec rake test` and `rbenv exec bundle exec standardrb` pass in `packages/better_auth`, unless a failure is documented as pre-existing with exact output.
