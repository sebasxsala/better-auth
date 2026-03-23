# frozen_string_literal: true

require_relative "lib/better_auth/rails/version"

Gem::Specification.new do |spec|
  spec.name = "better_auth_rails"
  spec.version = BetterAuth::Rails::VERSION
  spec.authors = ["Your Name"]
  spec.email = ["your.email@example.com"]

  spec.summary = "Alias for better_auth-rails"
  spec.description = "Please use better_auth-rails instead."
  spec.homepage = "https://github.com/sebasxsala/better-auth"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sebasxsala/better-auth"

  spec.files = [
    "lib/better_auth_rails.rb",
    "LICENSE.md"
  ]
  spec.require_paths = ["lib"]

  spec.add_dependency "better_auth-rails"
end
