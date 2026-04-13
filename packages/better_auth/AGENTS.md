# AGENTS.md - better_auth (Core)

This is the core authentication library. It is **framework-agnostic** and depends only on Rack. No Rails code belongs here.

## What This Package Is

`better_auth` is the Ruby translation of the upstream `packages/better-auth` TypeScript package. It contains all core authentication logic: session management, token handling, OAuth flows, user/account models, password hashing, and the plugin system.

When implementing features, always reference `upstream/packages/better-auth/` for the original TypeScript implementation.

## Constraints

- **No Rails dependencies.** This gem must work with any Rack-based app (Sinatra, Hanami, Roda, etc.)
- **No RSpec.** This package uses Minitest exclusively.
- Runtime deps are limited to: `rack`, `json`, `jwt`, `bcrypt`

## Development

```bash
bundle install
bundle exec rake test       # Run Minitest suite
bundle exec standardrb      # Check linting
bundle exec standardrb --fix # Auto-fix
bundle exec rake ci         # Full CI (lint + test)
```

## Directory Structure

```
lib/
  better_auth.rb              # Main entry point, autoloads
  better_auth/
    version.rb                # BetterAuth::VERSION
    core.rb                   # Core module loader
    core/                     # Core auth logic (sessions, tokens, OAuth, etc.)

test/
  test_helper.rb              # Minitest setup, shared helpers
  better_auth_test.rb         # Top-level smoke tests
  better_auth/
    <module>_test.rb          # Tests mirror lib/ structure
```

## Namespace

- **Gem name**: `better_auth`
- **Require path**: `require "better_auth"`
- **Top-level module**: `BetterAuth`
- Everything lives under `BetterAuth::` (e.g., `BetterAuth::Session`, `BetterAuth::OAuth::Provider`)

## Testing

- Framework: **Minitest**
- Files: `test/**/*_test.rb`
- Run: `bundle exec rake test`
- All public APIs must have tests
- Prefer integration-style tests that exercise real flows over unit tests with mocks
- Use `docker-compose up -d` for database-dependent tests

## Translating from Upstream

When porting a feature from `upstream/packages/better-auth/src/`:

1. Read the TypeScript source thoroughly
2. Understand the data flow and side effects
3. Write the Ruby equivalent using idiomatic patterns
4. Ensure the same edge cases are handled
5. Write tests that verify the same behavior (check `upstream/packages/better-auth/src/**/*.test.ts` for test cases to port)
