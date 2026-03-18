# Contributing to Better Auth Ruby

Thank you for your interest in contributing to Better Auth Ruby!
This guide will help you get started with the contribution process.

## Code of Conduct

This project and everyone participating in it is governed by our
[Code of Conduct](/CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code.

## Project Structure

```
lib/
  better_auth.rb              # Main entry point
  better_auth/
    version.rb                # Version constant
    core.rb                   # Core module loader
    core/                     # Core authentication logic
    rails.rb                  # Rails adapter entry
    rails/                    # Rails-specific code

test/                       # Core library tests (Minitest)
spec/                       # Rails adapter tests (RSpec)
```

## Development Guidelines

When contributing to Better Auth Ruby:

* Keep changes focused. Large PRs are harder to review.
* Follow Ruby conventions and idioms
* Ensure all code passes StandardRB linting
* Write tests for new features
* Maintain backward compatibility when possible

## Getting Started

1. Fork the repository to your GitHub account

2. Clone your fork locally:

   ```bash
   git clone https://github.com/your-username/better-auth-ruby.git
   cd better-auth-ruby
   ```

3. Install Ruby (3.2+ required, 3.3 recommended)

   We recommend using a Ruby version manager like rbenv, rvm, or asdf.

4. Install dependencies:

   ```bash
   bundle install
   ```

5. Run tests to ensure everything is working:

   ```bash
   bundle exec rake ci
   ```

## Development Workflow

1. Create a new branch for your changes:

   ```bash
   git checkout -b type/description
   # Example: git checkout -b feat/oauth-provider
   ```

   Branch type prefixes:

   * `feat/` - New features
   * `fix/` - Bug fixes
   * `docs/` - Documentation changes
   * `refactor/` - Code refactoring
   * `test/` - Test-related changes
   * `chore/` - Build process or tooling changes

2. Make your changes following the code style guidelines

3. Run the linter:

   ```bash
   bundle exec standardrb --fix
   ```

4. Add tests for your changes

5. Run the test suite:

   ```bash
   # Run all tests
   bundle exec rake ci

   # Run only core tests
   bundle exec rake test

   # Run only Rails adapter tests
   bundle exec rspec
   ```

6. Commit your changes with a descriptive message:

   ```text
   feat(rails): add current_user helper method

   fix(core): resolve token validation issue
   ```

7. Push your branch to your fork

8. Open a pull request against the **main** branch

## Code Style

We use [StandardRB](https://github.com/standardrb/standard) for code formatting and linting.
Before committing, please ensure your code passes:

```bash
# Check code style
bundle exec standardrb

# Auto-fix issues
bundle exec standardrb --fix
```

### Ruby Style Guidelines

* Use 2 spaces for indentation
* Use `snake_case` for methods, variables, and file names
* Use `CamelCase` for classes and modules
* Use `SCREAMING_SNAKE_CASE` for constants
* Add `frozen_string_literal: true` pragma to all Ruby files
* Prefer single quotes for strings without interpolation
* Avoid unnecessary Ruby features (unless they improve readability)

## Testing Guidelines

### Core Library (Minitest)

Located in `test/` directory:

```ruby
# test/better_auth/some_feature_test.rb
require_relative "test_helper"

class SomeFeatureTest < Minitest::Test
  def test_something
    assert_equal expected, actual
  end
end
```

### Rails Adapter (RSpec)

Located in `spec/` directory:

```ruby
# spec/better_auth/rails/some_feature_spec.rb
require "spec_helper"

RSpec.describe BetterAuth::Rails::SomeFeature do
  it "does something" do
    expect(subject).to eq expected
  end
end
```

## Pull Request Process

1. Create a draft pull request early to facilitate discussion
2. Reference any related issues in your PR description
3. Ensure all tests pass and the build is successful
4. Update documentation as needed
5. Keep your PR focused on a single feature or bug fix
6. Be responsive to code review feedback

## Security Issues

For security-related issues, please email [security@better-auth.com](mailto:security@better-auth.com).
Include a detailed description of the vulnerability and steps to reproduce it.
All reports will be reviewed and addressed promptly.
For more information, see our [security documentation](/SECURITY.md).
