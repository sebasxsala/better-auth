# Better Auth Rails

Rails adapter for Better Auth Ruby. Provides seamless integration with Ruby on Rails applications including middleware, controller helpers, and generators.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'better_auth-rails'
```

Optional compatibility package (underscore naming):

```ruby
gem 'better_auth_rails'
```

And then execute:

```bash
bundle install
```

## Usage

### Basic Setup

Add to your `config/application.rb`:

```ruby
require 'better_auth/rails'
```

Compatibility require is also supported:

```ruby
require 'better_auth_rails'
```

Or in your Gemfile:

```ruby
gem 'better_auth-rails', require: 'better_auth/rails'
```

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
  before_action :authenticate_user!

  def index
    @posts = current_user.posts
  end

  def create
    @post = current_user.posts.build(post_params)
    # ...
  end
end
```

### Available Methods

- `current_user` - Returns the currently authenticated user
- `authenticate_user!` - Redirects to login if not authenticated
- `user_signed_in?` - Returns true if user is authenticated
- `sign_in(user)` - Signs in a user
- `sign_out` - Signs out the current user

### Configuration

Create an initializer `config/initializers/better_auth.rb`:

```ruby
BetterAuth.configure do |config|
  config.secret_key = Rails.application.credentials.secret_key_base
  config.database_url = Rails.application.credentials.database_url
  
  # Optional: Configure session store
  config.session_store = :redis
  config.session_options = {
    url: ENV['REDIS_URL']
  }
end
```

### Routes

Mount the Better Auth engine in your routes:

```ruby
Rails.application.routes.draw do
  mount BetterAuth::Rails::Engine => '/auth'
  
  # Your routes...
end
```

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
