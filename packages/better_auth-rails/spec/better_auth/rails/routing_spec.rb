# frozen_string_literal: true

require_relative "../../spec_helper"
require "action_dispatch"
require "rack/mock"

class BetterAuthRailsFakeRouteSet
  attr_reader :calls

  def initialize
    @calls = []
  end

  def mount(app, at:)
    calls << [app, at]
  end
end

RSpec.describe BetterAuth::Rails::Routing do
  it "mounts the configured Better Auth Rack app at /api/auth by default" do
    routes = BetterAuthRailsFakeRouteSet.new
    auth = instance_double(BetterAuth::Auth)

    routes.extend(described_class)
    routes.better_auth(auth: auth)

    mounted_app, mount_path = routes.calls.first
    expect(mounted_app).to be_a(BetterAuth::Rails::MountedApp)
    expect(mounted_app.instance_variable_get(:@auth)).to eq(auth)
    expect(mount_path).to eq("/api/auth")
  end

  it "dispatches core endpoints through a real Rails route mount" do
    auth = BetterAuth.auth(secret: secret)
    app = build_route_set do
      better_auth auth: auth
    end

    response = Rack::MockRequest.new(app).get("/api/auth/ok")

    expect(response.status).to eq(200)
    expect(JSON.parse(response.body)).to eq("ok" => true)
  end

  it "builds the auth instance with a custom base path when mounted at a custom path" do
    BetterAuth::Rails.configure do |config|
      config.secret = secret
      config.database = :memory
    end
    app = build_route_set do
      better_auth at: "/auth"
    end

    response = Rack::MockRequest.new(app).get("/auth/ok")

    expect(response.status).to eq(200)
    expect(JSON.parse(response.body)).to eq("ok" => true)
  end

  it "dispatches plugin endpoints through the Rails mount wrapper" do
    plugin = BetterAuth::Plugin.new(
      id: "rails-plugin",
      endpoints: {
        rails_probe: BetterAuth::Endpoint.new(path: "/rails-probe", method: "GET") do |ctx|
          ctx.set_cookie("rails_probe", "1", path: "/")
          {mounted: true, path: ctx.path, cookie: ctx.get_cookie("rails_input")}
        end
      }
    )
    auth = BetterAuth.auth(secret: secret, plugins: [plugin])
    app = build_route_set do
      better_auth auth: auth
    end

    response = Rack::MockRequest.new(app).get("/api/auth/rails-probe", "HTTP_COOKIE" => "rails_input=present")

    expect(response.status).to eq(200)
    expect(JSON.parse(response.body)).to eq("mounted" => true, "path" => "/rails-probe", "cookie" => "present")
    expect(response["set-cookie"]).to include("rails_probe=1")
  end

  it "keeps core origin checks active for mutating mounted requests with cookies" do
    auth = BetterAuth.auth(secret: secret)
    app = build_route_set do
      better_auth auth: auth
    end

    response = Rack::MockRequest.new(app).post(
      "/api/auth/sign-out",
      "CONTENT_TYPE" => "application/json",
      "HTTP_COOKIE" => "better-auth.session_token=stale-token",
      :input => "{}"
    )

    expect(response.status).to eq(403)
    expect(JSON.parse(response.body)).to eq("code" => "FORBIDDEN", "message" => "Missing or null Origin")
  end

  def build_route_set(&block)
    ActionDispatch::Routing::Mapper.include(BetterAuth::Rails::Routing)
    ActionDispatch::Routing::RouteSet.new.tap { |routes| routes.draw(&block) }
  end

  def secret
    "test-secret-that-is-long-enough-for-validation"
  end

  after do
    BetterAuth::Rails.instance_variable_set(:@auth, nil)
    BetterAuth::Rails.instance_variable_set(:@configuration, nil)
  end
end
