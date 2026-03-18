# AGENTS.md

This file provides guidance to AI assistants (Claude Code, Cursor, etc.) when working with code in this repository.

## Project Overview

Better Auth is a comprehensive, framework-agnostic authentication framework for Ruby. It provides a complete set of authentication and authorization features with a plugin ecosystem.

## Development Commands

```bash
# Install dependencies
bundle install

# Run linter
bundle exec standardrb

# Fix linting issues
bundle exec standardrb --fix

# Run tests (Minitest)
bundle exec rake test

# Run full CI
bundle exec rake ci
```

## Architecture

### Directory Structure

* `lib/better_auth.rb` - Main entry point
* `lib/better_auth/core/` - Core authentication logic (framework-agnostic)
* `test/` - Core library tests (Minitest)

**Note:** Rails adapter is in a separate package (`packages/better_auth-rails`)

## Code Style

* Linter: StandardRB (Ruby community standard)
* Use 2 spaces for indentation
* Follow Ruby naming conventions:
  - Files/directories: `snake_case.rb`
  - Classes/Modules: `CamelCase`
  - Methods/variables: `snake_case`
  - Constants: `SCREAMING_SNAKE_CASE`
* Prefer composition over inheritance
* Use frozen_string_literal: true pragma

## Testing

* This package uses Minitest for testing
* Test files should end with `_test.rb`
* Keep tests focused and fast
* Use descriptive test names

**Note:** Rails adapter testing is in `packages/better_auth-rails` using RSpec

## Documentation

* Please update the documentation when you make changes to the public API
* Use YARD format for documentation comments
* Include code examples in documentation

## Git Workflow

* PRs should target the `main` branch
* Commit format: `feat(scope): description` or `fix(scope): description`, following Conventional Commits
* Use `docs:` for documentation, `chore:` for non-functional changes

## After Everything is Done

**Unless the user asked for it or you are working on CI, DO NOT COMMIT**

* Make sure `bundle exec standardrb` passes
* Make sure all tests pass
