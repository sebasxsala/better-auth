# frozen_string_literal: true

require_relative "../../spec_helper"

RSpec.describe "BetterAuth::Sinatra extension" do
  include Rack::Test::Methods

  attr_accessor :app

  after do
    BetterAuth::Sinatra.reset!
  end

  it "mounts core Better Auth routes at /api/auth by default" do
    self.app = build_app

    get "/api/auth/ok"

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("ok" => true)
  end

  it "mounts core Better Auth routes at a custom path" do
    self.app = build_app(mount_path: "/auth")

    get "/auth/ok"

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("ok" => true)
  end

  it "dispatches plugin endpoints through the Sinatra mount" do
    plugin = BetterAuth::Plugin.new(
      id: "sinatra-plugin",
      endpoints: {
        sinatra_probe: BetterAuth::Endpoint.new(path: "/sinatra-probe", method: "GET") do |ctx|
          ctx.set_cookie("sinatra_probe", "1", path: "/")
          {mounted: true, path: ctx.path, cookie: ctx.get_cookie("sinatra_input")}
        end
      }
    )
    self.app = build_app(plugins: [plugin])

    get "/api/auth/sinatra-probe", {}, "HTTP_COOKIE" => "sinatra_input=present"

    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to eq("mounted" => true, "path" => "/sinatra-probe", "cookie" => "present")
    expect(last_response["set-cookie"]).to include("sinatra_probe=1")
  end

  it "keeps core origin checks active for mutating mounted requests with cookies" do
    self.app = build_app

    post "/api/auth/sign-out", "{}", "CONTENT_TYPE" => "application/json", "HTTP_COOKIE" => "better-auth.session_token=stale-token"

    expect(last_response.status).to eq(403)
    expect(JSON.parse(last_response.body)).to eq("code" => "FORBIDDEN", "message" => "Missing or null Origin")
  end

  it "lets Sinatra helpers resolve the current Better Auth user from real cookies" do
    self.app = build_app
    sign_up_email("ada@example.com")

    get "/dashboard", {}, "HTTP_COOKIE" => cookie_header(last_response["set-cookie"])

    expect(last_response.status).to eq(200)
    data = JSON.parse(last_response.body)
    expect(data.fetch("authenticated")).to eq(true)
    expect(data.fetch("user").fetch("email")).to eq("ada@example.com")
  end

  it "halts protected Sinatra routes with 401 when no Better Auth user is present" do
    self.app = build_app

    get "/private"

    expect(last_response.status).to eq(401)
    expect(last_response.body).to eq("")
  end

  def build_app(mount_path: "/api/auth", plugins: [])
    secret = "sinatra-secret-that-is-long-enough-for-validation"

    Class.new(Sinatra::Base) do
      register BetterAuth::Sinatra

      set :environment, :test
      set :raise_errors, true
      set :show_exceptions, false

      better_auth at: mount_path do |config|
        config.secret = secret
        config.base_url = "http://example.org"
        config.database = :memory
        config.email_and_password = {enabled: true}
        config.plugins = plugins
      end

      get "/dashboard" do
        content_type :json
        JSON.generate(authenticated: authenticated?, user: current_user)
      end

      get "/private" do
        require_authentication
        "private"
      end
    end
  end

  def sign_up_email(email)
    post(
      "/api/auth/sign-up/email",
      JSON.generate(email: email, password: "password123", name: "Ada"),
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "http://example.org"
    )
    expect(last_response.status).to eq(200)
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end
