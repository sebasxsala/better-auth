# better_auth-mongo-adapter

MongoDB database adapter package for Better Auth Ruby.

## Installation

Add the gem and require the package before configuring auth:

```ruby
gem "better_auth-mongo-adapter"
```

```ruby
require "mongo"
require "better_auth/mongo_adapter"

mongo_client = Mongo::Client.new(ENV.fetch("BETTER_AUTH_MONGODB_URL"))

auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  database: BetterAuth::Adapters::MongoDB.new(
    database: mongo_client.database,
    client: mongo_client,
    transaction: false
  )
)
```

## Notes

This package depends on the official `mongo` gem. Keeping MongoDB support outside `better_auth` avoids installing MongoDB client dependencies for applications that only use SQL, Rails, Hanami, or in-memory storage.

The adapter stores Better Auth models in singular MongoDB collections by default, maps logical `id` values to Mongo `_id`, converts ObjectId-compatible ids through the Mongo driver, and supports the shared Better Auth database adapter contract.

Transactions are deployment-dependent. MongoDB multi-document transactions may
be unavailable on standalone servers and usually require a replica set plus
compatible driver/session settings. The setup example uses `transaction: false`;
enable transactions only when the MongoDB deployment supports them.

## Limits

By default, `find_many` calls without an explicit `limit:` are capped at 100 records. Configure the default with Better Auth's advanced database option:

```ruby
auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  advanced: {
    database: {
      default_find_many_limit: 250
    }
  },
  database: BetterAuth::Adapters::MongoDB.new(
    database: mongo_client.database,
    client: mongo_client,
    transaction: false
  )
)
```

The same default applies to one-to-many join lookups when the join config does not set `limit:`. Passing an explicit `limit:` to `find_many` or to the join config overrides the default.

One-to-one joins ignore one-to-many limits. They are returned as a single object or `nil`.
