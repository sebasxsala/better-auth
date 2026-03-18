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

Release now runs on `push` to `main` and follows this flow:

1. Run lint + tests for `better_auth` and `better_auth-rails`
2. Detect if `version.rb` changed in either package
3. Build gems and publish changed packages to RubyGems
4. Create and push git tag automatically (`vX.Y.Z`)
5. Create GitHub Release automatically

If no version changed, release jobs are skipped after tests.

```bash
# 1. Bump one or both versions
# packages/better_auth/lib/better_auth/version.rb
# packages/better_auth-rails/lib/better_auth/rails/version.rb

# 2. Commit and push to main
git add packages/better_auth/lib/better_auth/version.rb packages/better_auth-rails/lib/better_auth/rails/version.rb
git commit -m "chore: bump versions to 0.1.1"
git push origin main

# GitHub Actions handles publish + tag + GitHub Release
```

**Note:** If both versions are changed in the same release commit, they must match.

### Dry-run Release Validation

Use these to verify release packaging without publishing:

```bash
# Local dry-run build
make release-check

# CI dry-run (manual): Actions -> Release -> Run workflow -> dry_run=true
```

### Preview / Pre-release Versions

RubyGems supports pre-release versions like `0.2.0.beta.1` or `0.2.0.rc.1`.

To publish a preview:

1. Bump version(s) to a pre-release suffix
2. Push to `main`
3. Release workflow publishes that exact pre-release version

Clients can install with `--pre`.

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
