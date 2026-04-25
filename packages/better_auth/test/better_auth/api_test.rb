# frozen_string_literal: true

require "json"
require_relative "../test_helper"

class BetterAuthAPITest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_direct_api_runs_before_hooks_and_replaces_arrays
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            echo: BetterAuth::Endpoint.new(path: "/echo", method: "GET") do |ctx|
              {query: ctx.query}
            end
          }
        }
      ],
      hooks: {
        before: lambda do |ctx|
          next unless ctx.path == "/echo"

          {
            context: {
              query: {
                name: "from-hook",
                tags: ["hook"]
              }
            }
          }
        end
      }
    )

    response = auth.api.echo(query: {keep: "caller", tags: ["caller"]})

    assert_equal "from-hook", response[:query][:name]
    assert_equal "caller", response[:query][:keep]
    assert_equal ["hook"], response[:query][:tags]
  end

  def test_direct_api_before_hook_can_short_circuit
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            echo: BetterAuth::Endpoint.new(path: "/echo", method: "GET") { {ok: true} }
          }
        }
      ],
      hooks: {
        before: ->(_ctx) { {before: true} }
      }
    )

    assert_equal({before: true}, auth.api.echo)
  end

  def test_direct_api_runs_after_hooks_and_last_response_wins
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            echo: BetterAuth::Endpoint.new(path: "/echo", method: "GET") { {hello: "world"} }
          },
          hooks: {
            after: [
              {
                matcher: ->(ctx) { ctx.path == "/echo" },
                handler: ->(_ctx) { {hello: "plugin"} }
              }
            ]
          }
        }
      ],
      hooks: {
        after: ->(_ctx) { {hello: "user"} }
      }
    )

    assert_equal({hello: "plugin"}, auth.api.echo)
  end

  def test_direct_api_can_return_rack_response_headers_and_status
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            cookies: BetterAuth::Endpoint.new(path: "/cookies", method: "POST") do |ctx|
              ctx.set_status(201)
              ctx.set_cookie("session", "endpoint")
              {ok: true}
            end
          },
          hooks: {
            after: [
              {
                matcher: ->(ctx) { ctx.path == "/cookies" },
                handler: lambda do |ctx|
                  ctx.set_header("x-after", "yes")
                  ctx.set_cookie("after", "hook")
                  nil
                end
              }
            ]
          }
        }
      ]
    )

    data = auth.api.cookies(return_headers: true, return_status: true)

    assert_equal 201, data[:status]
    assert_equal({ok: true}, data[:response])
    assert_equal "yes", data[:headers]["x-after"]
    assert_includes data[:headers]["set-cookie"], "session=endpoint"
    assert_includes data[:headers]["set-cookie"], "after=hook"
    assert_equal ["session=endpoint", "after=hook"], data[:headers]["set-cookie"].split("\n")

    status, headers, body = auth.api.cookies(as_response: true)
    assert_equal 201, status
    assert_includes headers["set-cookie"], "session=endpoint"
    assert_equal({ok: true}, JSON.parse(body.join, symbolize_names: true))
  end

  def test_direct_api_errors_throw_unless_as_response_is_requested
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            fail: BetterAuth::Endpoint.new(path: "/fail", method: "GET") do |ctx|
              raise ctx.error("FORBIDDEN", message: "Blocked")
            end
          }
        }
      ]
    )

    assert_raises(BetterAuth::APIError) { auth.api.fail }

    status, _headers, body = auth.api.fail(as_response: true)
    assert_equal 403, status
    assert_equal({code: "FORBIDDEN", message: "Blocked"}, JSON.parse(body.join, symbolize_names: true))
  end
end
