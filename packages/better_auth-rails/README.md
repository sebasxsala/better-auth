# Better Auth Rails

Rails adapter for Better Auth Ruby. Provides seamless integration with Ruby on Rails applications including middleware, controller helpers, and generators.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "better_auth-rails"
```

### Defensive alias package

`better_auth_rails` is published only as a defensive alias package.

WARNING: This gem is an alias. Use `better_auth-rails`.

And then execute:

```bash
bundle install
```

## Usage

### Basic Setup

Add to your `config/application.rb`:

```ruby
require "better_auth/rails"
```

Compatibility require is also supported:

```ruby
require "better_auth_rails"
```

Or in your Gemfile:

```ruby
gem "better_auth-rails", require: "better_auth/rails"
```

### Initializer And Migration

Create the default initializer and base migration:

```bash
bin/rails generate better_auth:install
```

The same install path is available as a Rails task:

```bash
bin/rails better_auth:init
```

To generate only the base migration:

```bash
bin/rails generate better_auth:migration
bin/rails better_auth:generate:migration
```

The generators skip an existing `config/initializers/better_auth.rb` or existing `*_create_better_auth_tables.rb` migration instead of overwriting them.

### Configuration

The install generator creates `config/initializers/better_auth.rb`:

```ruby
BetterAuth::Rails.configure do |config|
  config.secret =
    Rails.application.credentials.dig(:better_auth, :secret) ||
    Rails.application.credentials.secret_key_base ||
    Rails.application.secret_key_base

  config.base_url = ENV["BETTER_AUTH_URL"]
  config.base_path = "/api/auth"
  config.database = ->(options) { BetterAuth::Rails::ActiveRecordAdapter.new(options) }
  config.plugins = []
end
```

The ActiveRecord adapter uses whichever database adapter the Rails app is already configured with, including PostgreSQL and MySQL.

### Routes

Mount the Better Auth Rack app in your routes:

```ruby
Rails.application.routes.draw do
  better_auth
end
```

By default this mounts at `/api/auth`. To customize the path:

```ruby
Rails.application.routes.draw do
  better_auth at: "/auth"
end
```

The Better Auth core router handles internal routes such as `/callback/:providerId`.

### Controller Helpers

Include the controller helpers in your ApplicationController:

```ruby
class ApplicationController < ActionController::Base
  include BetterAuth::Rails::ControllerHelpers
end
```

Now you have access to authentication methods:

```ruby
class PostsController < ApplicationController
  before_action :require_authentication

  def index
    @user = current_user
  end

  private

  def require_authentication
    head :unauthorized unless authenticated?
  end
end
```

### Available Methods

- `current_session` - Returns the current Better Auth session hash
- `current_user` - Returns the current Better Auth user hash
- `authenticated?` - Returns true when a user is present

## Development

### Setup

```bash
# Clone the monorepo
git clone --recursive https://github.com/sebasxsala/better-auth.git
cd better-auth/packages/better_auth-rails

# Install dependencies
bundle install
```

### Running Tests

```bash
# Run all tests
bundle exec rspec

# Run with coverage
COVERAGE=true bundle exec rspec

# Run specific test
bundle exec rspec spec/better_auth/rails/controller_helpers_spec.rb
```

### Code Style

We use StandardRB for linting:

```bash
# Check style
bundle exec standardrb

# Auto-fix issues
bundle exec standardrb --fix
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sebasxsala/better-auth.

When contributing:
1. Fork the repository
2. Create your feature branch (`git checkout -b feat/amazing-feature`)
3. Make sure tests pass (`bundle exec rspec`)
4. Ensure code style passes (`bundle exec standardrb`)
5. Commit your changes (`git commit -m 'feat: add amazing feature'`)
6. Push to the branch (`git push origin feat/amazing-feature`)
7. Open a Pull Request towards the `canary` branch

## License

The gem is available as open source under the terms of the MIT License.
