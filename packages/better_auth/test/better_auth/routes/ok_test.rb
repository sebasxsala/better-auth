# frozen_string_literal: true

require "json"
require "stringio"
require_relative "../../test_helper"

class BetterAuthRoutesOkTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_ok_direct_api_response
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    assert_equal({ok: true}, auth.api.ok)
  end

  def test_ok_rack_response
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    status, headers, body = auth.call(rack_env("GET", "/api/auth/ok"))

    assert_equal 200, status
    assert_equal "application/json", headers["content-type"]
    assert_equal({ok: true}, JSON.parse(body.join, symbolize_names: true))
  end

  private

  def rack_env(method, path, query: "")
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => query,
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(""),
      "CONTENT_LENGTH" => "0"
    }
  end
end
