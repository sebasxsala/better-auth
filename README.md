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
better-auth/                    # Workspace principal (este repo)
├── upstream/                   # Submódulo: better-auth TypeScript original
├── packages/
│   ├── better_auth/            # Gema: better_auth (core)
│   │   ├── lib/better_auth/
│   │   ├── test/               # Tests con Minitest
│   │   └── better_auth.gemspec
│   │
│   └── better_auth-rails/      # Gema: better_auth-rails (adapter)
│       ├── lib/better_auth/rails/
│       ├── spec/               # Tests con RSpec
│       └── better_auth-rails.gemspec
│
├── Gemfile                     # Workspace Gemfile (referencia packages)
├── Rakefile                    # Tareas del workspace
└── Makefile                    # Comandos de desarrollo
```

## Installation

### Core only (Rack-based apps)

```ruby
gem 'better_auth'
```

### With Rails

```ruby
gem 'better_auth-rails'  # Incluye better_auth automáticamente
```

## Development

### Quick Start

```bash
# 1. Clona el repositorio
git clone --recursive https://github.com/sebasxsala/better-auth.git
cd better-auth

# 2. Instala dependencias de todo el workspace
make install

# 3. Corre tests para verificar todo funciona
make ci
```

### Comandos del Workspace

```bash
# Ver todos los comandos
make help

# Desarrollo
make console          # Consola con todos los packages cargados
make lint            # Linting en todos los packages
make lint-fix        # Auto-fix de linting

# Testing
make test            # Tests de todo el workspace
make test-core       # Solo better_auth (Minitest)
make test-rails      # Solo better_auth-rails (RSpec)
make ci              # CI completo

# Bases de datos
make db-up           # Inicia PostgreSQL, MySQL, Redis
make db-down         # Detiene contenedores
```

### Trabajando en un Package Específico

```bash
# Entra al package
cd packages/better_auth

# Instala dependencias locales
bundle install

# Corre tests
bundle exec rake test

# Vuelve al workspace
cd ../..
```

## Git Workflow

### Estructura de Ramas

- **`main`** - Código estable, releases
- **`canary`** - Rama de desarrollo/integración
  - Los PRs de features van a `canary`
  - Cuando está estable, merge a `main` para release
- **`upstream`** - Referencia al repo original TypeScript (submódulo)

### Flujo de Trabajo

```bash
# 1. Crea tu feature branch desde canary
git checkout canary
git pull origin canary
git checkout -b feat/nueva-funcionalidad

# 2. Haces tus cambios
# ... código ...

# 3. Commit y push
git add .
git commit -m "feat(core): agrega soporte para X"
git push origin feat/nueva-funcionalidad

# 4. Crea PR hacia canary en GitHub

# 5. Una vez mergeado a canary y probado:
#    Merge canary → main y crea tag para release
```

### Actualizar el Submódulo Upstream

```bash
# Actualiza el submódulo a la última versión
cd upstream
git fetch origin
git checkout canary  # o main, según necesites
git pull origin canary
cd ..
git add upstream
git commit -m "chore: update upstream to latest canary"
```

## Release Process

### Release Automático (GitHub Actions)

El release se dispara al crear un tag:

```bash
# 1. Actualiza la versión en el package correspondiente
#    packages/better_auth/lib/better_auth/version.rb
#    o packages/better_auth-rails/lib/better_auth/rails/version.rb

# 2. Commit del cambio
git add packages/better_auth/lib/better_auth/version.rb
git commit -m "chore: bump better_auth to v0.1.1"

# 3. Crea y push el tag
git tag -a v0.1.1 -m "Release v0.1.1"
git push origin main --tags

# GitHub Actions publica automáticamente a RubyGems!
```

**Nota:** Cada package tiene su propio versionado independiente.

### Configuración de RubyGems

1. Ve a GitHub → Settings → Secrets → Actions
2. Agrega `RUBYGEMS_API_KEY` con tu API key
3. El workflow publica automáticamente

## Contributing

1. Fork el repositorio
2. Crea tu feature branch (`git checkout -b feat/amazing-feature`)
3. Commit tus cambios (`git commit -m 'feat: add amazing feature'`)
4. Push a la rama (`git push origin feat/amazing-feature`)
5. Abre un Pull Request hacia `canary`

## License

[MIT License](LICENSE.md)

## Security

Para reportar vulnerabilidades: security@better-auth.com
