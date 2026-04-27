# Better Auth Sinatra

Sinatra adapter for Better Auth Ruby. This package is a thin integration around
the framework-agnostic `better_auth` Rack core.

## Installation

```ruby
gem "better_auth-sinatra"
```

```bash
bundle install
```

## Setup

```ruby
require "sinatra/base"
require "better_auth/sinatra"

class App < Sinatra::Base
  register BetterAuth::Sinatra

  better_auth at: "/api/auth" do |config|
    config.secret = ENV.fetch("BETTER_AUTH_SECRET")
    config.base_url = ENV.fetch("BETTER_AUTH_URL")
    config.database = ->(options) {
      BetterAuth::Adapters::Postgres.new(options, url: ENV.fetch("DATABASE_URL"))
    }
    config.email_and_password = {enabled: true}
    config.plugins = []
  end

  get "/dashboard" do
    require_authentication
    current_user.fetch("email")
  end
end
```

The extension mounts the core Rack app at `/api/auth` by default. The core app
still owns routes such as `/ok`, `/sign-up/email`, `/sign-in/email`, and plugin
endpoints.

## Helpers

- `current_session`
- `current_user`
- `authenticated?`
- `require_authentication`

`require_authentication` halts with `401` when no Better Auth user is present.

## Rake Tasks

Load tasks from your app Rakefile:

```ruby
require "better_auth/sinatra/tasks"
```

Available tasks:

```bash
rake better_auth:install
rake better_auth:generate:migration
rake better_auth:migrate
rake better_auth:routes
```

`better_auth:install` creates `config/better_auth.rb`. SQL migrations are
generated under `db/better_auth/migrate`.

## Database Notes

Sinatra does not include a Rails-style database layer or migration command.
This adapter uses Better Auth core SQL adapters for migrations. Set
`BETTER_AUTH_DIALECT=postgres`, `mysql`, or `sqlite` when generating SQL.

ActiveRecord-backed Sinatra migrations are not supported yet. Apps that already
use `sinatra-activerecord` can still configure Better Auth manually, but the v1
Rake tasks do not emit ActiveRecord migrations.

## Development

```bash
cd packages/better_auth-sinatra
rbenv exec bundle exec rspec
RUBOCOP_CACHE_ROOT=/private/var/folders/7x/jrsz946d2w73n42fb1_ff5000000gn/T/rubocop_cache_sinatra rbenv exec bundle exec standardrb
```
