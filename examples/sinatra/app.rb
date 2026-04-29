# frozen_string_literal: true

require "bundler/setup"
require "sinatra/base"
require "better_auth"
require "better_auth/sinatra"

class App < Sinatra::Base
  configure do
    set :sessions, secret: ENV.fetch("SESSION_SECRET", "change-me-in-production")
  end

  get "/" do
    "Hello from Sinatra + Better Auth"
  end

  get "/protected" do
    # Placeholder for a protected route.
    # You can use BetterAuth::Sinatra helpers here once configured.
    "This should be protected"
  end
end

App.run! if __FILE__ == $0
