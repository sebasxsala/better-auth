# frozen_string_literal: true

# Rakefile del Workspace - Better Auth Ruby
# Permite ejecutar tareas en todos los packages

require "rake"

STANDARD_PATHS = [
  "Rakefile",
  "packages/better_auth/Rakefile",
  "packages/better_auth/lib",
  "packages/better_auth/test",
  "packages/better_auth-rails/Rakefile",
  "packages/better_auth-rails/lib",
  "packages/better_auth-rails/spec"
].freeze

# Tarea por defecto: ejecutar CI en todos los packages
desc "Run CI in all packages"
task :ci do
  puts "🔧 Running CI in workspace..."

  # Linting global
  puts "\n📋 Running linter..."
  sh "bundle exec standardrb #{STANDARD_PATHS.join(" ")}"

  # Tests de cada package
  puts "\n🧪 Running tests in packages/better_auth..."
  cd "packages/better_auth" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake ci"
  end

  puts "\n🧪 Running tests in packages/better_auth-rails..."
  cd "packages/better_auth-rails" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake ci"
  end

  puts "\n✅ Workspace CI completed successfully!"
end

desc "Install dependencies in all packages"
task :install do
  puts "📦 Installing workspace dependencies..."
  sh "bundle install"

  puts "\n📦 Installing packages/better_auth dependencies..."
  cd "packages/better_auth" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end

  puts "\n📦 Installing packages/better_auth-rails dependencies..."
  cd "packages/better_auth-rails" do
    sh "BUNDLE_GEMFILE=Gemfile bundle install"
  end
end

desc "Run linter across all packages"
task :lint do
  sh "bundle exec standardrb #{STANDARD_PATHS.join(" ")}"

  cd "packages/better_auth" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end

  cd "packages/better_auth-rails" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb"
  end
end

desc "Auto-fix linting issues across all packages"
task "lint:fix" do
  sh "bundle exec standardrb --fix #{STANDARD_PATHS.join(" ")}"

  cd "packages/better_auth" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end

  cd "packages/better_auth-rails" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec standardrb --fix"
  end
end

desc "Run tests in specific package"
task :test, [:package] do |t, args|
  package = args[:package]

  unless package
    puts "❌ Usage: rake test[package_name]"
    puts "   Example: rake test[better_auth]"
    exit 1
  end

  cd "packages/#{package}" do
    sh "BUNDLE_GEMFILE=Gemfile bundle exec rake test"
  end
end

desc "Clean all packages"
task :clean do
  sh "rm -rf Gemfile.lock"

  cd "packages/better_auth" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end

  cd "packages/better_auth-rails" do
    sh "rm -rf Gemfile.lock *.gem coverage/"
  end
end

task default: :ci
