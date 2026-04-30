# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthEndpointTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_endpoint_collects_status_headers_and_cookies
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(path: "/json", method: "GET") do |ctx|
      ctx.set_status(201)
      ctx.set_header("x-test", "yes")
      ctx.set_cookie("session", "value")

      {ok: true}
    end

    result = endpoint.call(context_for(auth, endpoint))

    assert_equal 201, result.status
    assert_equal({ok: true}, result.response)
    assert_equal "yes", result.headers["x-test"]
    assert_includes result.headers["set-cookie"], "session=value"
  end

  def test_endpoint_preserves_raw_rack_responses
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(path: "/raw", method: "GET") do
      [202, {"content-type" => "text/plain"}, ["accepted"]]
    end

    result = endpoint.call(context_for(auth, endpoint))

    assert result.raw_response?
    assert_equal [202, {"content-type" => "text/plain"}, ["accepted"]], result.to_rack_response
  end

  def test_endpoint_raises_api_errors_with_status_and_headers
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(path: "/error", method: "GET") do |ctx|
      raise ctx.error("BAD_REQUEST", message: "Nope", headers: {"x-error" => "yes"})
    end

    error = assert_raises(BetterAuth::APIError) { endpoint.call(context_for(auth, endpoint)) }

    assert_equal "BAD_REQUEST", error.status
    assert_equal 400, error.status_code
    assert_equal "Nope", error.message
    assert_equal "yes", error.headers["x-error"]
  end

  def test_endpoint_rejects_header_values_with_newlines
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(path: "/header", method: "GET") do |ctx|
      ctx.set_header("x-test", "safe\r\nset-cookie: injected=true")
      {ok: true}
    end

    error = assert_raises(BetterAuth::APIError) { endpoint.call(context_for(auth, endpoint)) }

    assert_equal "INTERNAL_SERVER_ERROR", error.status
    assert_equal "Invalid header value", error.message
  end

  def test_endpoint_applies_schema_parsers_before_handler
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    schema = Class.new do
      def parse(value)
        raise ArgumentError, "name is required" unless value["name"]

        value.merge("parsed" => true)
      end
    end.new
    endpoint = BetterAuth::Endpoint.new(path: "/profile", method: "POST", body_schema: schema) do |ctx|
      ctx.body
    end

    result = endpoint.call(context_for(auth, endpoint, body: {"name" => "Ada"}))

    assert_equal({"name" => "Ada", "parsed" => true}, result.response)
  end

  def test_endpoint_applies_all_schema_parsers_before_handler
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    parser = Class.new do
      def initialize(label)
        @label = label
      end

      def parse(value)
        value.merge("#{@label}_parsed" => true)
      end
    end
    endpoint = BetterAuth::Endpoint.new(
      path: "/profiles/:id",
      method: "POST",
      body_schema: parser.new("body"),
      query_schema: parser.new("query"),
      params_schema: parser.new("params"),
      headers_schema: parser.new("headers")
    ) do |ctx|
      {
        body: ctx.body,
        query: ctx.query,
        params: ctx.params,
        headers: ctx.headers.slice("x-name", "headers-parsed")
      }
    end

    result = endpoint.call(
      context_for(
        auth,
        endpoint,
        body: {"name" => "Ada"},
        query: {"page" => "1"},
        params: {"id" => "user-1"},
        headers: {"x_name" => "Ada"}
      )
    )

    assert_equal({"name" => "Ada", "body_parsed" => true}, result.response[:body])
    assert_equal({"page" => "1", "query_parsed" => true}, result.response[:query])
    assert_equal({"id" => "user-1", "params_parsed" => true}, result.response[:params])
    assert_equal({"x-name" => "Ada", "headers-parsed" => true}, result.response[:headers])
  end

  def test_endpoint_schema_errors_become_bad_request_api_errors
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    endpoint = BetterAuth::Endpoint.new(path: "/profile", method: "POST", body_schema: ->(_value) { false }) do
      {ok: true}
    end

    error = assert_raises(BetterAuth::APIError) { endpoint.call(context_for(auth, endpoint, body: {})) }

    assert_equal "BAD_REQUEST", error.status
    assert_equal "Validation Error", error.message
  end

  private

  def context_for(auth, endpoint, body: {}, query: {}, params: {}, headers: {})
    BetterAuth::Endpoint::Context.new(
      path: endpoint.path,
      method: "GET",
      query: query,
      body: body,
      params: params,
      headers: headers,
      context: auth.context
    )
  end
end
