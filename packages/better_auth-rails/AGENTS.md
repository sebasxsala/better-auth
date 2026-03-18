# AGENTS.md - Better Auth Rails Package

**⚠️ CRITICAL: Always read this file when editing files in packages/better_auth-rails/**

This file provides guidance to AI assistants (Claude Code, Cursor, etc.) when working with code in this directory.

**Note:** CLAUDE.md is a symlink to this file. Both contain the same information.

## Project Overview

This is the **Rails adapter** for Better Auth Ruby. It provides Rails-specific functionality including:
- Middleware integration
- Controller helpers (`current_user`, `authenticate_user!`, etc.)
- Rails generators
- Session management for Rails applications

## Important: Framework-Specific Code Only

This package should **ONLY** contain Rails-specific code. Framework-agnostic authentication logic belongs in `packages/better_auth/`.

## Development Commands

```bash
# Install dependencies
bundle install

# Run linter
bundle exec standardrb

# Fix linting issues
bundle exec standardrb --fix

# Run tests (RSpec)
bundle exec rspec

# Run full CI
bundle exec rake ci
```

## Architecture

### Directory Structure

* `lib/better_auth/rails.rb` - Main entry point
* `lib/better_auth/rails/` - Rails-specific adapters
  * `middleware/` - Rack middleware for Rails
  * `controller_helpers.rb` - `current_user`, `authenticate_user!`, etc.
  * `generators/` - Rails generators
* `spec/` - RSpec tests

**Note:** Core authentication logic is in `packages/better_auth/`

## Code Style

* Linter: StandardRB (Ruby community standard)
* Use 2 spaces for indentation
* Follow Ruby naming conventions:
  - Files/directories: `snake_case.rb`
  - Classes/Modules: `CamelCase`
  - Methods/variables: `snake_case`
  - Constants: `SCREAMING_SNAKE_CASE`
* Use frozen_string_literal: true pragma

## Testing

* This package uses **RSpec** for testing (better Rails integration)
* Test files should end with `_spec.rb`
* Place tests in `spec/` directory
* Keep tests focused and fast
* Mock external dependencies when possible

**Note:** Core package testing is in `packages/better_auth` using Minitest

## Dependencies

### Runtime Dependencies

* `better_auth` - The core authentication library
* `railties` - Rails framework
* `activesupport` - Rails support library

### Development Dependencies

* `rspec` - Testing framework
* `standardrb` - Linting
* `rake` - Build tasks

## Documentation

* Update README.md when adding public APIs
* Use YARD format for method documentation
* Include usage examples for controller helpers
* Document generator usage

## Rails Integration Patterns

### Controller Helpers

When adding controller helpers, follow this pattern:

```ruby
module BetterAuth
  module Rails
    module ControllerHelpers
      def current_user
        # Implementation
      end
    end
  end
end
```

### Middleware

Middleware should be Rack-compliant:

```ruby
module BetterAuth
  module Rails
    class Middleware
      def initialize(app)
        @app = app
      end

      def call(env)
        # Implementation
        @app.call(env)
      end
    end
  end
end
```

## Git Workflow

* PRs should target the `canary` branch
* Commit format: `feat(scope): description` or `fix(scope): description`, following Conventional Commits
* Use `docs:` for documentation, `chore:` for non-functional changes
* Tag commits affecting Rails integration with `[rails]` in description if helpful

## After Everything is Done

**Unless the user asked for it or you are working on CI, DO NOT COMMIT**

* Make sure `bundle exec standardrb` passes
* Make sure `bundle exec rspec` passes
* Update README.md if adding new features
* Ensure compatibility with supported Rails versions

## Cross-Package Development

When making changes that affect both core and Rails adapter:

1. **Start with core changes** in `packages/better_auth/`
2. **Test core independently** first
3. **Update Rails adapter** to use new core features
4. **Run full workspace tests**: `make test` from root
5. **Commit separately** for each package

## Links

* **Core Package:** `packages/better_auth/`
* **Workspace Root:** `AGENTS.md` in repository root
* **Issues:** https://github.com/sebasxsala/better-auth/issues
