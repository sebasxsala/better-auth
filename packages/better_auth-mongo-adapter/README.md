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
