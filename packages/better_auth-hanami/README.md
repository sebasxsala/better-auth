# Better Auth Hanami

Hanami adapter for Better Auth Ruby. It mounts the core Rack auth object inside
Hanami, uses Hanami's ROM/Sequel database gateway for persistence, renders
ROM::SQL migrations, generates Hanami relations/repos for app queries, and
provides action helpers plus generator tasks.

## Installation

```ruby
gem "better_auth-hanami"
```

```bash
bundle install
```

## Setup

Load the task file from your app Rakefile if your app does not already load
`lib/tasks`:

```ruby
# Rakefile
require "better_auth/hanami"
load Gem.loaded_specs.fetch("better_auth-hanami").full_gem_path + "/lib/tasks/better_auth.rake"
```

Generate the provider, route wiring, task wrapper, settings, relations/repos,
and base migration:

```bash
bundle exec rake better_auth:init
```

Run Hanami migrations:

```bash
bin/hanami db migrate
```

When you add plugins that introduce schema tables or fields, regenerate both
the migration and the app query objects before migrating a new app:

```bash
bundle exec rake better_auth:generate:migration
bundle exec rake better_auth:generate:relations
```

## Configuration

The install generator creates `config/providers/better_auth.rb`:

```ruby
Hanami.app.register_provider(:better_auth) do
  prepare do
    require "better_auth/hanami"
  end

  start do
    BetterAuth::Hanami.configure do |config|
      config.secret = target["settings"].better_auth_secret
      config.base_url = target["settings"].better_auth_url
      config.base_path = "/api/auth"
      config.database = ->(options) {
        BetterAuth::Hanami::SequelAdapter.from_container(target, options)
      }
      config.email_and_password = {enabled: true}
      config.plugins = []
    end

    auth = BetterAuth::Hanami.auth
    register "better_auth.auth", auth
    register "better_auth.rack_app", BetterAuth::Hanami::MountedApp.new(auth, mount_path: BetterAuth::Hanami.configuration.base_path)
  end
end
```

## Routes

The generated `config/routes.rb` includes:

```ruby
require "better_auth/hanami/routing"

module Bookshelf
  class Routes < Hanami::Routes
    include BetterAuth::Hanami::Routing

    better_auth
  end
end
```

By default this mounts Better Auth at `/api/auth`. Customize the path:

```ruby
better_auth at: "/auth"
```

## Action Helpers

Include helpers in your base action:

```ruby
class Action < Hanami::Action
  include BetterAuth::Hanami::ActionHelpers
end
```

Use them from an action:

```ruby
def handle(request, response)
  return unless require_authentication(request, response)

  response.body = current_user(request).fetch("email")
end
```

## Relations And Repos

Better Auth uses `BetterAuth::Hanami::SequelAdapter` for its own reads and
writes. The generated Hanami relations/repos are for your application code when
you want to inspect or query Better Auth tables directly:

```ruby
users = Hanami.app["relations.users"].to_a
user = Hanami.app["repos.user_repo"].users.by_pk(user_id).one
```

If you prefer a custom persistence implementation, configure it directly:

```ruby
BetterAuth::Hanami.configure do |config|
  config.database = ->(options) { MyBetterAuthAdapter.new(options) }
end
```

## Limitations

- Supports Hanami 2.3+ only. Better Auth core depends on Rack 3, and Hanami 2.3 is the first Hanami line that allows Rack 3.
- Hanami 1.x and Hanami 2.2/Rack 2 apps are out of scope for this adapter.
- The stable command surface is Rake/generator based. A `hanami better_auth ...` command is not exposed because the current public guides do not document a stable third-party Hanami CLI extension API.
- Apps created with `--skip-db` can use memory storage for development or tests, but production apps should configure Hanami DB or pass an explicit Better Auth adapter.

## Development

```bash
cd packages/better_auth-hanami
rbenv exec bundle exec rspec
rbenv exec bundle exec standardrb
```
