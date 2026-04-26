# frozen_string_literal: true

require_relative "../../spec_helper"

class BetterAuthRailsHelperController
  include BetterAuth::Rails::ControllerHelpers

  attr_reader :request

  def initialize(request)
    @request = request
  end
end

RSpec.describe BetterAuth::Rails::ControllerHelpers do
  after do
    BetterAuth::Rails.instance_variable_set(:@auth, nil)
    BetterAuth::Rails.instance_variable_set(:@configuration, nil)
  end

  it "exposes the current Better Auth session and user from the Rack request" do
    request = instance_double("Request", env: {
      "better_auth.session" => {
        session: {"id" => "session-1"},
        user: {"id" => "user-1", "email" => "ada@example.com"}
      }
    })
    controller = BetterAuthRailsHelperController.new(request)

    expect(controller.current_session).to eq({"id" => "session-1"})
    expect(controller.current_user).to eq({"id" => "user-1", "email" => "ada@example.com"})
    expect(controller.authenticated?).to be(true)
  end

  it "resolves the session from Better Auth cookies when request env is empty" do
    request = instance_double(
      "Request",
      env: {},
      path: "/posts",
      request_method: "GET",
      query_parameters: {},
      get_header: "better-auth.session_token=signed-token"
    )
    controller = BetterAuthRailsHelperController.new(request)
    session = {
      session: {"id" => "session-1"},
      user: {"id" => "user-1"}
    }

    BetterAuth::Rails.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
    end
    allow(BetterAuth::Session).to receive(:find_current).and_return(session)

    expect(controller.current_user).to eq({"id" => "user-1"})
    expect(request.env["better_auth.session"]).to eq(session)
  end
end
