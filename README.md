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

It provides a complete set of authentication and authorization features out of the box, with a plugin ecosystem that simplifies adding advanced functionalities -- 2FA, multi-tenant support, OAuth providers, and more.

## Packages

| Gem | Description | Install |
|-----|-------------|---------|
| [`better_auth`](packages/better_auth/) | Core authentication library. Framework-agnostic, Rack-based. | `gem "better_auth"` |
| [`better_auth-rails`](packages/better_auth-rails/) | Rails adapter. Middleware, helpers, generators. | `gem "better_auth-rails"` |

## Quick Start

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

```bash
git clone --recursive https://github.com/sebasxsala/better-auth.git
cd better-auth
make install
make ci
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development guide.

## Monorepo Structure

```
better-auth/
├── packages/
│   ├── better_auth/            # Core gem (Rack-based)
│   └── better_auth-rails/      # Rails adapter gem
├── upstream/                   # Git submodule: TypeScript better-auth (reference)
├── Gemfile                     # Workspace Gemfile
├── Rakefile                    # Workspace tasks
└── Makefile                    # Developer shortcuts
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

If you discover a security vulnerability, please email security@better-auth.com. See [SECURITY.md](SECURITY.md) for the full policy.

## License

[MIT License](LICENSE.md)
