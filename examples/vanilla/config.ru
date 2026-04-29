# frozen_string_literal: true

require "bundler/setup"
require "better_auth"

class App
  def call(env)
    req = Rack::Request.new(env)

    case req.path_info
    when "/"
      [200, {"Content-Type" => "text/plain"}, ["Hello from Vanilla Rack + Better Auth"]]
    when "/health"
      [200, {"Content-Type" => "text/plain"}, ["OK"]]
    else
      [404, {"Content-Type" => "text/plain"}, ["Not Found"]]
    end
  end
end

run App.new
