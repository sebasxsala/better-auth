# frozen_string_literal: true

require_relative "lib/better_auth/version"

Gem::Specification.new do |spec|
  spec.name = "better_auth"
  spec.version = BetterAuth::VERSION
  spec.authors = ["Your Name"]
  spec.email = ["your.email@example.com"]

  spec.summary = "Comprehensive authentication framework for Ruby/Rack"
  spec.description = "Better Auth is a comprehensive, framework-agnostic authentication library for Ruby. It provides a complete set of features out of the box with a plugin ecosystem."
  spec.homepage = "https://github.com/sebasxsala/better-auth"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sebasxsala/better-auth"
  spec.metadata["changelog_uri"] = "https://github.com/sebasxsala/better-auth/blob/main/packages/better_auth/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "https://github.com/sebasxsala/better-auth/issues"

  # Specify which files should be added to the gem when it is released.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) ||
        f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Core runtime dependencies
  spec.add_dependency "rack", "~> 3.0"
  spec.add_dependency "json", "~> 2.0"
  spec.add_dependency "jwt", "~> 2.8"
  spec.add_dependency "bcrypt", "~> 3.1"

  # Development dependencies
  spec.add_development_dependency "bundler", "~> 2.5"
  spec.add_development_dependency "minitest", "~> 5.25"
  spec.add_development_dependency "standardrb", "~> 1.0"
  spec.add_development_dependency "rake", "~> 13.2"
  spec.add_development_dependency "simplecov", "~> 0.22"
end
