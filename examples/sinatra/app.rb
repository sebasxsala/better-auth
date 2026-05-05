# frozen_string_literal: true

require "bundler/setup"
require "sinatra/base"
require "better_auth"
require "better_auth/sinatra"

class App < Sinatra::Base
  register BetterAuth::Sinatra

  set :environment, ENV.fetch("RACK_ENV", "development").to_sym

  better_auth at: "/api/auth" do |config|
    config.secret = ENV.fetch("BETTER_AUTH_SECRET", "change-me-sinatra-secret-12345678901234567890")
    config.base_url = ENV.fetch("BETTER_AUTH_URL", "http://localhost:4567")
    config.database = :memory
    config.email_and_password = {enabled: true}
  end

  get "/" do
    "Hello from Sinatra + Better Auth"
  end

  get "/protected" do
    require_authentication
    "Signed in as #{current_user.fetch("email")}"
  end
end

App.run! if __FILE__ == $0
