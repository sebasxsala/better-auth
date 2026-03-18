<p align="center">
  <h2 align="center">
    Better Auth Ruby
  </h2>

  <p align="center">
    The most comprehensive authentication framework for Ruby
    <br />
    <a href="https://better-auth.com"><strong>Learn more »</strong></a>
    <br />
    <br />
    <a href="https://discord.gg/better-auth">Discord</a>
    ·
    <a href="https://better-auth.com">Website</a>
    ·
    <a href="https://github.com/sebasxsala/better-auth/issues">Issues</a>
  </p>

[![Gem](https://img.shields.io/gem/v/better_auth?style=flat&colorA=000000&colorB=000000)](https://rubygems.org/gems/better_auth)
[![GitHub stars](https://img.shields.io/github/stars/sebasxsala/better-auth?style=flat&colorA=000000&colorB=000000)](https://github.com/sebasxsala/better-auth/stargazers)
</p>

## About the Project

Better Auth Ruby is a comprehensive authentication and authorization library for Ruby. It provides a complete set of features out of the box and includes a plugin ecosystem that simplifies adding advanced functionalities with minimal code.

### Features

- **Framework Agnostic Core**: Works with any Rack-based application
- **Rails Integration**: First-class Rails support with middleware and helpers
- **Session Management**: Secure session handling
- **Multiple Authentication Methods**: Email/password, OAuth, JWT, and more
- **Two-Factor Authentication**: TOTP and WebAuthn support
- **Plugin System**: Extensible architecture for custom features

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'better_auth'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install better_auth
```

## Usage

### Basic Setup

```ruby
require 'better_auth'

# Configure Better Auth
BetterAuth.configure do |config|
  config.secret_key = ENV['BETTER_AUTH_SECRET']
  config.database_url = ENV['DATABASE_URL']
end
```

### Rails Integration

Add to your Gemfile:

```ruby
gem 'better_auth', require: 'better_auth/rails'
```

Then in your ApplicationController:

```ruby
class ApplicationController < ActionController::Base
  include BetterAuth::Rails::ControllerHelpers
end
```

Now you have access to `current_user` and authentication methods:

```ruby
class PostsController < ApplicationController
  before_action :authenticate_user!

  def index
    @posts = current_user.posts
  end
end
```

## Development

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/sebasxsala/better-auth.git
cd better-auth/packages/better_auth

# 2. Install dependencies
make install
# or: bundle install

# 3. Run tests to verify everything works
make ci
```

### Common Make Commands

We use a **Makefile** to simplify commands. All have explanatory comments:

```bash
# View all available commands with description
make help

# Development
make console          # Interactive console with gem loaded
make lint            # Check code style
make lint-fix        # Auto-fix style issues

# Testing
make test            # Run all tests
make test-core       # Only core tests (Minitest)
make test-coverage   # Tests with coverage
make ci              # Full CI (lint + test)

# Databases for testing
make db-up           # Start PostgreSQL, MySQL, Redis
make db-down         # Stop containers
```

### Branch Workflow

This project uses a branch model similar to the upstream:

**Main Branches:**

- **`main`**: Stable code, ready for production
- **`canary`**: Development/integration branch (like "development" but specific name)
  - "Canary" comes from "canary in a coal mine" - where changes are tested before production
  - Feature PRs go to `canary`
  - When `canary` is stable, merge to `main` for release

**Typical workflow:**

```bash
# 1. Create your feature branch from canary
git checkout canary
git pull origin canary
git checkout -b feat/new-feature

# 2. Make your changes and commits
# ... code ...
git add .
git commit -m "feat(core): add support for X"

# 3. Push and create PR towards canary
git push origin feat/new-feature
# Create PR on GitHub towards canary

# 4. Once merged to canary and tested,
#    merge canary → main for release
```

**Why canary instead of development?**

- Common name in projects with frequent releases
- Suggests it's an "experimental" version that might break
- Allows multiple levels: feature → canary → main

### How CI/CD Works

**Pull Requests:**
- Each PR runs: lint + tests on Ruby 3.2 and 3.3
- Everything must pass before merging

**Automatic Release (GitHub Actions):**

Release is triggered automatically when you create a git tag:

```bash
# STEP 1: Update version in lib/better_auth/version.rb
# Example: VERSION = "0.1.1"

# STEP 2: Commit the version change
git add lib/better_auth/version.rb
git commit -m "chore: bump version to 0.1.1"

# STEP 3: Create and push the tag
git tag -a v0.1.1 -m "Release v0.1.1"
git push origin main --tags

# STEP 4: GitHub Actions automatically:
# - Runs tests
# - Builds the gem
# - Publishes to RubyGems
# - Creates GitHub Release with changelog
```

**Required GitHub Configuration:**

1. Go to Settings → Secrets and variables → Actions
2. Add `RUBYGEMS_API_KEY` with your RubyGems API key
3. The workflow `.github/workflows/release.yml` does the rest

### Manual Release (without GitHub Actions)

Only if you need to do a manual release:

```bash
# 1. Update version.rb
# 2. Build the gem
gem build better_auth.gemspec

# 3. Publish (you need to be logged into RubyGems)
gem push better_auth-*.gem

# 4. Create and push the tag
git tag -a v0.1.1 -m "Release v0.1.1"
git push origin --tags
```

### Project Structure

```
lib/
  better_auth.rb              # Entry point
  better_auth/
    version.rb                # Gem version
    core.rb                   # Core loader
    core/                     # Core logic (framework-agnostic)

test/                       # Core tests (Minitest)
```

**Conventions:**
- Core: Framework-agnostic, uses Minitest
- All code goes through StandardRB (Ruby style guide)

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sebasxsala/better-auth. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/sebasxsala/better-auth/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Security

If you discover a security vulnerability within Better Auth Ruby, please send an e-mail to [security@better-auth.com](mailto:security@better-auth.com).

All reports will be promptly addressed, and you'll be credited accordingly.
