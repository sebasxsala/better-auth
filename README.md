<p align="center">
  <h2 align="center">
    Better Auth Ruby
  </h2>

  <p align="center">
    The most comprehensive authentication framework for Ruby
    <br />
    <a href="https://better-auth.com"><strong>Learn more</strong></a>
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

## About

Better Auth Ruby is a faithful Ruby port of [better-auth](https://github.com/better-auth/better-auth), the comprehensive authentication framework originally built for TypeScript. Same philosophy, same features, idiomatic Ruby.

It provides a complete set of authentication and authorization features out of the box, with a plugin ecosystem that simplifies adding advanced functionalities: 2FA, multi-tenant support, OAuth providers, and more.

## Packages

| Gem | Description | Install |
|-----|-------------|---------|
| [`better_auth`](packages/better_auth/) | Core authentication library. Framework-agnostic, Rack-based. | `gem "better_auth"` |
| [`better_auth-rails`](packages/better_auth-rails/) | Rails adapter. Middleware, helpers, generators. | `gem "better_auth-rails"` |

## Quick start

### Rails

```ruby
# Gemfile
gem "better_auth-rails"
```

```bash
bundle install
```

### Rack (Sinatra, Hanami, Roda, etc.)

```ruby
# Gemfile
gem "better_auth"
```

```bash
bundle install
```

## Development

### Clone and verify

```bash
git clone --recursive https://github.com/sebasxsala/better-auth.git
cd better-auth
make install
make ci
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for the full workflow.

### Workspace commands

```bash
make help            # All Makefile targets
make console         # IRB with packages loaded
make lint            # StandardRB across packages
make lint-fix        # Auto-fix
make test            # Same as make ci (lint + tests)
make test-core       # better_auth only (Minitest)
make test-rails      # better_auth-rails only (RSpec)
make ci              # Full CI
make db-up           # PostgreSQL, MySQL, Redis (docker-compose)
make db-down
make release-check   # Build gems locally without publishing
```

### One package

```bash
cd packages/better_auth
bundle install
bundle exec rake test
```

## Monorepo layout

```
better-auth/
├── upstream/                   # Submodule: upstream TypeScript better-auth
├── packages/
│   ├── better_auth/            # Core gem (Minitest)
│   └── better_auth-rails/      # Rails adapter (RSpec)
├── Gemfile
├── Rakefile
└── Makefile
```

## Git workflow

- **`canary`** -- day-to-day development; open PRs here.
- **`main`** -- stable line; releases and CI publish run from here when versions bump.
- **`upstream/`** -- git submodule (reference only).

```bash
git checkout canary
git pull origin canary
git checkout -b feat/my-change
# ... commit ...
git push -u origin feat/my-change
# Open PR → canary
```

### Update the submodule

```bash
cd upstream
git fetch origin
git checkout v1.4.x   # or another tag/branch you track
cd ..
git add upstream
git commit -m "chore: update upstream reference"
```

## Release

Releases are automated with GitHub Actions on push to **`main`** when `version.rb` changes. The Rails adapter is published as both **`better_auth-rails`** and **`better_auth_rails`** (compatibility alias).

Details: [RELEASING.md](RELEASING.md).

```bash
# Bump version(s), merge to main, push — workflow publishes + tags when versions change
```

Dry-run locally: `make release-check`. In CI: run the Release workflow with `dry_run=true`.

## Contributing

1. Fork the repo
2. Branch from `canary`
3. Run `make ci` before pushing
4. Open a PR to **`canary`**

## Security

Report vulnerabilities to security@better-auth.com. See [SECURITY.md](SECURITY.md).

## License

[MIT License](LICENSE.md)
