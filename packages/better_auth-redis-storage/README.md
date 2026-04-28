# better_auth-redis-storage

Redis secondary storage package for Better Auth Ruby.

## Installation

Add the gem and require the package before configuring auth:

```ruby
gem "better_auth-redis-storage"
```

```ruby
require "redis"
require "better_auth/redis_storage"

redis = Redis.new(url: ENV.fetch("REDIS_URL"))

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: :memory,
  secondary_storage: BetterAuth::RedisStorage.new(client: redis)
)
```

## Notes

This package depends on the official `redis` gem. Keeping Redis storage outside `better_auth` avoids installing Redis client dependencies for applications that do not use secondary storage.

`secondary_storage` is used by Better Auth for session payload storage, active-session indexes, and rate limiting when `rate_limit: { storage: "secondary-storage" }` is configured.

