# frozen_string_literal: true

require_relative "../../spec_helper"

class BetterAuthHanamiAction
  include BetterAuth::Hanami::ActionHelpers
end

RSpec.describe BetterAuth::Hanami::ActionHelpers do
  let(:action) { BetterAuthHanamiAction.new }

  after do
    BetterAuth::Hanami.instance_variable_set(:@auth, nil)
    BetterAuth::Hanami.instance_variable_set(:@configuration, nil)
  end

  it "exposes the current session and user from the Rack request env" do
    request = fake_request({"better_auth.session" => {session: {"id" => "session-1"}, user: {"id" => "user-1"}}})

    expect(action.current_session(request)).to eq({"id" => "session-1"})
    expect(action.current_user(request)).to eq({"id" => "user-1"})
    expect(action.authenticated?(request)).to be(true)
  end

  it "resolves and caches session data from Better Auth cookies" do
    BetterAuth::Hanami.configure do |config|
      config.secret = secret
      config.database = :memory
      config.base_url = "http://localhost:2300"
      config.email_and_password = {enabled: true}
    end
    signup_headers = sign_up_headers
    request = fake_request({}, cookie: cookie_header(signup_headers.fetch("set-cookie")))

    expect(action.current_user(request)).to include("email" => "ada@example.com")
    expect(request.env["better_auth.session"]).to include(:session, :user)
  end

  it "halts with unauthorized status when authentication is required and missing" do
    request = fake_request({"better_auth.session" => nil})
    response = Struct.new(:status).new

    expect(action.require_authentication(request, response)).to be(false)
    expect(response.status).to eq(401)
  end

  def sign_up_headers
    status, headers, = BetterAuth::Hanami.auth.call(
      rack_env("POST", "/api/auth/sign-up/email", body: JSON.generate(email: "ada@example.com", password: "password123", name: "Ada"))
    )
    expect(status).to eq(200)
    headers
  end

  def fake_request(env, cookie: nil)
    Struct.new(:env, :path, :request_method, :params, :headers) do
      def get_header(name)
        return headers["cookie"] if name == "HTTP_COOKIE"

        nil
      end
    end.new(env, "/dashboard", "GET", {}, {"cookie" => cookie})
  end

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

  def secret
    "test-secret-that-is-long-enough-for-validation"
  end
end
