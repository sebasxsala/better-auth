# CLAUDE.md

This file provides guidance to Claude Code when working with the Better Auth Core package.

## Project Overview

This is the core package of Better Auth Ruby - a comprehensive authentication framework for Ruby/Rack applications.

## Key Principles

1. **Framework Agnostic**: This core library should work with any Rack-based application without framework dependencies
2. **No Rails Code**: Rails-specific code belongs in `packages/better_auth-rails`
3. **Standard Ruby Conventions**: Follow standard Ruby idioms and conventions
4. **Minitest Only**: This package uses only Minitest for testing

## Development Workflow

```bash
# Setup
bundle install

# Development
bundle exec standardrb --fix    # Format and fix linting
bundle exec rake test           # Run core tests
bundle exec rake ci             # Run full CI suite
```

## Code Organization

```
lib/
  better_auth.rb              # Main entry point
  better_auth/
    version.rb                # Version constant
    core.rb                   # Core module loader
    core/
      # Core authentication logic (Rack-based only)
```

## Naming Conventions

- **Gem name**: `better_auth` (RubyGems)
- **Require path**: `better_auth`
- **Namespace**: `BetterAuth`
- **Rails adapter**: Located in `packages/better_auth-rails` (separate gem)

## Testing Guidelines

- Write tests for all public APIs using Minitest
- Test files: `test/**/*_test.rb`
- Aim for high test coverage but prioritize meaningful tests
- Do NOT add RSpec tests here (use `packages/better_auth-rails` for that)

## Documentation

- Use YARD format for method documentation
- Include usage examples for public APIs
- Keep README.md updated with basic usage

## Linting

This project uses StandardRB. Run `bundle exec standardrb` to check and `bundle exec standardrb --fix` to auto-fix.

## Do Not

- Do not add Rails-specific code here
- Do not add RSpec tests here
- Do not use camelCase for file names
- Do not commit without running tests
- Do not add framework-specific dependencies
