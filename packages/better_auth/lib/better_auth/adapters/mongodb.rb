# frozen_string_literal: true

begin
  require "better_auth/mongo_adapter"
rescue LoadError => error
  raise if error.path && error.path != "better_auth/mongo_adapter"

  raise LoadError, "BetterAuth::Adapters::MongoDB requires the better_auth-mongo-adapter gem. Add `gem \"better_auth-mongo-adapter\"` and `require \"better_auth/mongo_adapter\"`."
end
