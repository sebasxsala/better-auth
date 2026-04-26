# frozen_string_literal: true

require_relative "../../spec_helper"

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

    expect(routes.calls).to eq([[auth, "/api/auth"]])
  end
end
