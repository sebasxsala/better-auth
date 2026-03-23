# AGENTS.md - Better Auth Rails Package

**⚠️ CRITICAL: Always read this file when editing files in packages/better_auth-rails/**

## What is this package?

This is the **Rails adapter** for Better Auth Ruby. It provides Rails-specific integrations:
- Middleware integration
- Controller helpers (`current_user`, `authenticate_user!`, etc.)
- Rails generators
- Session management

**Framework-agnostic logic belongs in `packages/better_auth/`, not here.**

## Upstream Reference

**Always check `upstream/` before implementing or modifying features.**

The TypeScript implementation is the source of truth. Your workflow:

1. **Find the feature** in `upstream/` (check `packages/better-auth/src/` and framework integrations)
2. **Understand how it works** in TypeScript
3. **Translate to Ruby/Rails** following Rails conventions and best practices
4. **Adapt idiomatically** - make it feel native to Rails, not a literal translation

## Development Commands

```bash
bundle install        # Install dependencies
bundle exec rspec     # Run tests (RSpec)
bundle exec standardrb  # Run linter
bundle exec standardrb --fix  # Fix linting issues
```

## Directory Structure

* `lib/better_auth/rails.rb` - Main entry point
* `lib/better_auth/rails/` - Rails-specific code
  * `middleware/` - Rack middleware
  * `controller_helpers.rb` - Controller helpers
  * `generators/` - Rails generators
* `spec/` - RSpec tests

## Code Style

* StandardRB for linting
* `frozen_string_literal: true` in all files
* snake_case for files/methods, CamelCase for classes

## After Everything is Done

**Unless the user asked for it, DO NOT COMMIT**

* Make sure `bundle exec standardrb` passes
* Make sure `bundle exec rspec` passes
