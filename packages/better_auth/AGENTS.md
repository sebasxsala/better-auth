# AGENTS.md - Better Auth Core Package

**⚠️ CRITICAL: Always read this file when editing files in packages/better_auth/**

## What is this package?

This is the **core gem** of Better Auth Ruby - a Ruby port of the TypeScript [better-auth](https://github.com/better-auth/better-auth) library. It contains framework-agnostic authentication logic built on Rack.

## Upstream Reference

**Always check `upstream/` before implementing or modifying features.**

The TypeScript implementation in `upstream/packages/better-auth/` is the source of truth. Your workflow should be:

1. **Find the feature** in `upstream/packages/better-auth/src/`
2. **Understand how it works** in TypeScript
3. **Translate to Ruby** following Ruby/Rails best practices
4. **Adapt idiomatically** - don't do a literal translation, make it feel native to Ruby

Key upstream directories:
- `upstream/packages/better-auth/src/` - Core auth logic
- `upstream/packages/better-auth/src/plugins/` - Plugin implementations

## Development Commands

```bash
bundle install          # Install dependencies
bundle exec rake test   # Run tests (Minitest)
bundle exec standardrb  # Run linter
bundle exec standardrb --fix  # Fix linting issues
```

## Directory Structure

* `lib/better_auth.rb` - Main entry point
* `lib/better_auth/core/` - Core authentication logic
* `test/` - Tests (Minitest)

## Code Style

* StandardRB for linting
* `frozen_string_literal: true` in all files
* snake_case for files/methods, CamelCase for classes

## After Everything is Done

**Unless the user asked for it, DO NOT COMMIT**

* Make sure `bundle exec standardrb` passes
* Make sure `bundle exec rake test` passes
