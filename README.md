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

Better Auth Ruby is a comprehensive authentication and authorization library for Ruby. This is a **monorepo** containing multiple gems:

- **`better_auth`** - Core authentication library (framework-agnostic, Rack-based)
- **`better_auth-rails`** - Rails adapter with middleware and helpers

## Monorepo Structure

```
better-auth/                    # Main workspace (this repo)
├── upstream/                   # Submodule: original better-auth TypeScript
├── packages/
│   ├── better_auth/            # Gem: better_auth (core)
│   │   ├── lib/better_auth/
│   │   ├── test/               # Tests with Minitest
│   │   └── better_auth.gemspec
│   │
│   └── better_auth-rails/      # Gem: better_auth-rails (adapter)
│       ├── lib/better_auth/rails/
│       ├── spec/               # Tests with RSpec
│       └── better_auth-rails.gemspec
│
├── Gemfile                     # Workspace Gemfile (references packages)
├── Rakefile                    # Workspace tasks
└── Makefile                    # Development commands
```

## Installation

### Core only (Rack-based apps)

```ruby
gem 'better_auth'
```

### With Rails

```ruby
gem 'better_auth-rails'  # Includes better_auth automatically
```

## Development

### Quick Start

```bash
# 1. Clone the repository
git clone --recursive https://github.com/sebasxsala/better-auth.git
cd better-auth

# 2. Install dependencies for the entire workspace
make install

# 3. Run tests to verify everything works
make ci
```

### Workspace Commands

```bash
# View all commands
make help

# Development
make console          # Console with all packages loaded
make lint            # Linting in all packages
make lint-fix        # Auto-fix linting issues

# Testing
make test            # Tests for entire workspace
make test-core       # Only better_auth (Minitest)
make test-rails      # Only better_auth-rails (RSpec)
make ci              # Full CI

# Databases
make db-up           # Start PostgreSQL, MySQL, Redis
make db-down         # Stop containers
```

### Working on a Specific Package

```bash
# Enter the package
cd packages/better_auth

# Install local dependencies
bundle install

# Run tests
bundle exec rake test

# Return to workspace
cd ../..
```

## Git Workflow

### Branch Structure

- **`main`** - Stable code, releases
- **`canary`** - Development/integration branch
  - Feature PRs go to `canary`
  - When stable, merge to `main` for release
- **`upstream`** - Reference to original TypeScript repo (submodule)

### Workflow

```bash
# 1. Create your feature branch from canary
git checkout canary
git pull origin canary
git checkout -b feat/new-feature

# 2. Make your changes
# ... code ...

# 3. Commit and push
git add .
git commit -m "feat(core): add support for X"
git push origin feat/new-feature

# 4. Create PR towards canary on GitHub

# 5. Once merged to canary and tested:
#    Merge canary → main and create tag for release
```

### Updating the Upstream Submodule

```bash
# Update submodule to latest version
cd upstream
git fetch origin
git checkout canary  # or main, as needed
git pull origin canary
cd ..
git add upstream
git commit -m "chore: update upstream to latest canary"
```

## Release Process

### Automatic Release (GitHub Actions)

Release is triggered by creating a tag:

```bash
# 1. Update version in the corresponding package
#    packages/better_auth/lib/better_auth/version.rb
#    or packages/better_auth-rails/lib/better_auth/rails/version.rb

# 2. Commit the change
git add packages/better_auth/lib/better_auth/version.rb
git commit -m "chore: bump better_auth to v0.1.1"

# 3. Create and push the tag
git tag -a v0.1.1 -m "Release v0.1.1"
git push origin main --tags

# GitHub Actions automatically publishes to RubyGems!
```

**Note:** Each package has its own independent versioning.

### RubyGems Configuration

1. Go to GitHub → Settings → Secrets → Actions
2. Add `RUBYGEMS_API_KEY` with your API key
3. The workflow publishes automatically

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feat/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request towards `canary`

## License

[MIT License](LICENSE.md)

## Security

To report vulnerabilities: security@better-auth.com
