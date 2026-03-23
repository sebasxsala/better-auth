# frozen_string_literal: true

require_relative "lib/better_auth/rails/version"

Gem::Specification.new do |spec|
  spec.name = "better_auth-rails"
  spec.version = BetterAuth::Rails::VERSION
  spec.authors = ["Sebastian Sala"]
  spec.email = ["sebastian.sala.tech@gmail.com"]

  spec.summary = "Rails adapter for Better Auth"
  spec.description = "Rails integration for Better Auth Ruby. Provides middleware, controller helpers, and generators."
  spec.homepage = "https://github.com/sebasxsala/better-auth"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sebasxsala/better-auth"
  spec.metadata["changelog_uri"] = "https://github.com/sebasxsala/better-auth/blob/main/packages/better_auth-rails/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "https://github.com/sebasxsala/better-auth/issues"

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) ||
        f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Runtime dependencies
  spec.add_dependency "better_auth", "~> 0.1"
  spec.add_dependency "railties", ">= 6.0"
  spec.add_dependency "activesupport", ">= 6.0"

  # Development dependencies
  spec.add_development_dependency "bundler", "~> 2.5"
  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "standardrb", "~> 1.0"
  spec.add_development_dependency "rake", "~> 13.2"
  spec.add_development_dependency "simplecov", "~> 0.22"
end
