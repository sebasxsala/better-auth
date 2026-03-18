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
    <a href="https://github.com/better-auth/better-auth-ruby/issues">Issues</a>
  </p>

[![Gem](https://img.shields.io/gem/v/better_auth?style=flat&colorA=000000&colorB=000000)](https://rubygems.org/gems/better_auth)
[![GitHub stars](https://img.shields.io/github/stars/better-auth/better-auth-ruby?style=flat&colorA=000000&colorB=000000)](https://github.com/better-auth/better-auth-ruby/stargazers)
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
# 1. Clona el repositorio
git clone https://github.com/better-auth/better-auth-ruby.git
cd better-auth-ruby

# 2. Instala dependencias
make install
# o: bundle install

# 3. Corre tests para verificar todo funciona
make ci
```

### Comandos Comunes con Make

Usamos un **Makefile** para simplificar los comandos. Todos tienen comentarios explicativos:

```bash
# Ver todos los comandos disponibles con descripción
make help

# Desarrollo
make console          # Consola interactiva con la gema cargada
make lint            # Revisa estilo de código
make lint-fix        # Corrige estilo automáticamente

# Testing
make test            # Ejecuta todos los tests
make test-core       # Solo tests del core (Minitest)
make test-rails      # Solo tests Rails (RSpec)
make test-coverage   # Tests con cobertura
make ci              # CI completo (lint + test)

# Bases de datos para testing
make db-up           # Inicia PostgreSQL, MySQL, Redis
make db-down         # Detiene contenedores
```

### Flujo de Trabajo de Ramas

Este proyecto usa un modelo de ramas similar al del upstream:

**Ramas principales:**

- **`main`**: Código estable, listo para producción
- **`canary`**: Rama de desarrollo/integración (como "development" pero con nombre específico)
  - "Canary" viene de "canary in a coal mine" - es donde prueban cambios antes de ir a producción
  - Los PRs de features van a `canary`
  - Cuando `canary` está estable, se mergea a `main` para release

**Flujo de trabajo típico:**

```bash
# 1. Crea tu feature branch desde canary
git checkout canary
git pull origin canary
git checkout -b feat/nueva-funcionalidad

# 2. Haces tus cambios y commits
# ... código ...
git add .
git commit -m "feat(core): agrega soporte para X"

# 3. Push y creas PR hacia canary
git push origin feat/nueva-funcionalidad
# Crear PR en GitHub hacia canary

# 4. Una vez mergeado a canary y probado,
#    se mergea canary → main para el release
```

**Por qué canary en vez de development?**

- Es un nombre común en proyectos que hacen releases frecuentes
- Sugiere que es una versión "experimental" que puede romperse
- Permite tener múltiples niveles: feature → canary → main

### Cómo Funciona el CI/CD

**Pull Requests:**
- Cada PR ejecuta: lint + tests en Ruby 3.2 y 3.3
- Debe pasar todo antes de poder mergear

**Release Automático (GitHub Actions):**

El release se dispara automáticamente cuando creas un git tag:

```bash
# PASO 1: Actualiza la versión en lib/better_auth/version.rb
# Ejemplo: VERSION = "0.1.1"

# PASO 2: Commitea el cambio de versión
git add lib/better_auth/version.rb
git commit -m "chore: bump version to 0.1.1"

# PASO 3: Crea y push el tag
git tag -a v0.1.1 -m "Release v0.1.1"
git push origin main --tags

# PASO 4: GitHub Actions automáticamente:
# - Corre tests
# - Construye la gema
# - Publica a RubyGems
# - Crea GitHub Release con changelog
```

**Configuración necesaria en GitHub:**

1. Ve a Settings → Secrets and variables → Actions
2. Agrega `RUBYGEMS_API_KEY` con tu API key de RubyGems
3. El workflow `.github/workflows/release.yml` hace el resto

### Release Manual (sin GitHub Actions)

Solo si necesitas hacer un release manualmente:

```bash
# 1. Actualiza version.rb
# 2. Construye la gema
gem build better_auth.gemspec

# 3. Publica (necesitas estar logueado en RubyGems)
gem push better_auth-*.gem

# 4. Crea el tag y push
git tag -a v0.1.1 -m "Release v0.1.1"
git push origin --tags
```

### Estructura del Proyecto

```
lib/
  better_auth.rb              # Entry point
  better_auth/
    version.rb                # Versión de la gema
    core.rb                   # Core loader
    core/                     # Lógica core (framework-agnostic)
    rails.rb                  # Rails adapter entry
    rails/                    # Código específico de Rails

test/                       # Tests del core (Minitest)
spec/                       # Tests de Rails (RSpec)
```

**Convenciones:**
- Core: Framework-agnostic, usa Minitest
- Rails: Adapter específico, usa RSpec para mejor integración
- Todo código pasa por StandardRB (Ruby style guide)

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/better-auth/better-auth-ruby. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/better-auth/better-auth-ruby/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Security

If you discover a security vulnerability within Better Auth Ruby, please send an e-mail to [security@better-auth.com](mailto:security@better-auth.com).

All reports will be promptly addressed, and you'll be credited accordingly.
