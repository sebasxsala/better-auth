# AGENTS.md - better_auth-rails (Rails Adapter)

This is the Rails adapter for Better Auth. It bridges the core `better_auth` gem with Rails conventions: middleware, controller helpers, generators, and configuration DSL.

## What This Package Is

`better_auth-rails` makes `better_auth` feel native in a Rails app. It provides:

- Rack middleware integration via Railtie
- Controller helpers (`current_user`, `authenticate!`, etc.)
- Rails generators for setup and migrations
- Configuration through `config/initializers/better_auth.rb`
- ActiveRecord integration for user/session models

This does **not** reimplement auth logic -- it delegates everything to `better_auth` core.

## Constraints

- **Depends on `better_auth` core.** Never duplicate core logic here.
- **Rails >= 6.0** support (via `railties` and `activesupport`)
- **RSpec only.** This package uses RSpec, not Minitest.

## Development

```bash
bundle install
bundle exec rspec            # Run RSpec suite
bundle exec standardrb       # Check linting
bundle exec standardrb --fix # Auto-fix
```

## Directory Structure

```
lib/
  better_auth/
    rails.rb                  # Main entry point
    rails/
      version.rb              # BetterAuth::Rails::VERSION
      railtie.rb              # Rails integration hooks
      middleware.rb            # Rack middleware for Rails
      controller_helpers.rb   # Helpers mixed into controllers
      generators/             # Rails generators

spec/
  spec_helper.rb              # RSpec setup
  better_auth/
    rails_spec.rb             # Top-level specs
    rails/
      <module>_spec.rb        # Specs mirror lib/ structure
```

## Namespace

- **Gem name**: `better_auth-rails`
- **Require path**: `require "better_auth/rails"`
- **Top-level module**: `BetterAuth::Rails`

## Testing

- Framework: **RSpec**
- Files: `spec/**/*_spec.rb`
- Run: `bundle exec rspec`
- Test Rails integration with a minimal Rails app fixture when needed
- Prefer real Rails middleware stack tests over mocked request/response objects
