# frozen_string_literal: true

require_relative "../../spec_helper"

RSpec.describe "BetterAuth::Hanami Sequel base routes" do
  let(:secret) { "test-secret-that-is-long-enough-for-validation" }

  it "runs signup, signin, and get-session routes against Sequel persistence" do
    db = Sequel.sqlite
    config = BetterAuth::Configuration.new(secret: secret, database: :memory)
    apply_migration(db, config)
    auth = BetterAuth.auth(
      base_url: "http://localhost:2300",
      secret: secret,
      database: ->(options) { BetterAuth::Hanami::SequelAdapter.new(options, connection: db) },
      email_and_password: {enabled: true}
    )

    signup_status, signup_headers, signup_body = auth.call(
      rack_env("POST", "/api/auth/sign-up/email", body: JSON.generate(email: "Ada@Example.com", password: "password123", name: "Ada"))
    )
    signup_data = JSON.parse(signup_body.join)

    signin_status, signin_headers, signin_body = auth.call(
      rack_env("POST", "/api/auth/sign-in/email", body: JSON.generate(email: "ada@example.com", password: "password123"))
    )
    signin_data = JSON.parse(signin_body.join)
    cookie = cookie_header(signin_headers.fetch("set-cookie"))

    session_status, _session_headers, session_body = auth.call(
      rack_env("GET", "/api/auth/get-session", body: "", extra_headers: {"HTTP_COOKIE" => cookie})
    )
    session_data = JSON.parse(session_body.join)

    expect(signup_status).to eq(200)
    expect(signup_headers.fetch("set-cookie")).to include("better-auth.session_token=")
    expect(signup_data.fetch("user").fetch("email")).to eq("ada@example.com")
    expect(signin_status).to eq(200)
    expect(signin_data.fetch("user").fetch("id")).to eq(signup_data.fetch("user").fetch("id"))
    expect(session_status).to eq(200)
    expect(session_data.fetch("user").fetch("email")).to eq("ada@example.com")
  end

  # rubocop:disable Security/Eval
  def apply_migration(db, config)
    require "rom-sql"
    gateway = ROM::SQL::Gateway.new(db)
    migration = ROM::SQL.with_gateway(gateway) do
      eval(BetterAuth::Hanami::Migration.render(config), binding, __FILE__, __LINE__)
    end
    migration.apply(db, :up)
  end
  # rubocop:enable Security/Eval

  def rack_env(method, path, body:, content_type: "application/json", extra_headers: {})
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "2300",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(body),
      "CONTENT_TYPE" => content_type,
      "CONTENT_LENGTH" => body.bytesize.to_s,
      "HTTP_ORIGIN" => "http://localhost:2300"
    }.merge(extra_headers)
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end
