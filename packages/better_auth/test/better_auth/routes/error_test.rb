# frozen_string_literal: true

require "stringio"
require "uri"
require_relative "../../test_helper"

class BetterAuthRoutesErrorTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_error_page_sanitizes_description
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    attack = "<script>alert(1)</script>"

    status, headers, body = auth.call(
      rack_env(
        "GET",
        "/api/auth/error",
        query: URI.encode_www_form(error: "TEST", error_description: attack)
      )
    )

    html = body.join
    assert_equal 200, status
    assert_equal "text/html", headers["content-type"]
    refute_includes html, "<script>"
    assert_includes html, "&lt;script&gt;"
  end

  def test_error_page_replaces_invalid_code_with_unknown
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    _status, _headers, body = auth.call(
      rack_env("GET", "/api/auth/error", query: URI.encode_www_form(error: "<script>"))
    )

    html = body.join
    assert_includes html, "UNKNOWN"
    refute_includes html, "<script>"
  end

  def test_error_page_redirects_to_configured_error_url
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      on_api_error: {error_url: "http://localhost:3000/custom-error"}
    )

    status, headers, body = auth.call(
      rack_env(
        "GET",
        "/api/auth/error",
        query: URI.encode_www_form(error: "TEST", error_description: "bad things")
      )
    )

    assert_equal 302, status
    assert_equal "http://localhost:3000/custom-error?error=TEST&error_description=bad+things", headers["location"]
    assert_equal [""], body
  end

  def test_error_direct_api_can_return_html_response
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    status, headers, body = auth.api.error(
      query: {error: "DIRECT"},
      as_response: true
    )

    assert_equal 200, status
    assert_equal "text/html", headers["content-type"]
    assert_includes body.join, "DIRECT"
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
