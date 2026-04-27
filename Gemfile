# frozen_string_literal: true

# Workspace Gemfile - Better Auth Ruby Monorepo
# Este Gemfile permite desarrollar todos los packages localmente

source "https://rubygems.org"

ruby file: "packages/better_auth/.ruby-version"

# Referencia local a los packages para desarrollo
# Esto permite trabajar en todos los packages simultáneamente
gem "better_auth", path: "packages/better_auth"
gem "better_auth-rails", path: "packages/better_auth-rails"
gem "better_auth-hanami", path: "packages/better_auth-hanami"

# Dependencias de desarrollo del workspace
group :development, :test do
  # Linting
  gem "standardrb", "~> 1.0"

  # Testing (usados por los packages)
  gem "minitest", "~> 5.25"
  gem "rspec", "~> 3.13"
  gem "pg", "~> 1.5"
  gem "mysql2", "~> 0.5"
  gem "sqlite3", "~> 2.0"
  gem "mongo", "~> 2.21"
  gem "sequel", "~> 5.83"
  gem "hanami", ">= 2.3", "< 2.4"
  gem "hanami-router", ">= 2.3", "< 3"
  gem "rom-sql", ">= 3.7", "< 4"
  gem "tiny_tds", "~> 2.1"

  # Build tasks
  gem "rake", "~> 13.2"

  # Cobertura
  gem "simplecov", "~> 0.22", require: false
end
