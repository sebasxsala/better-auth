# frozen_string_literal: true

require "json"
require_relative "../test_helper"

class BetterAuthRouterTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_rack_router_serves_ok_under_base_path
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    status, headers, body = auth.call(rack_env("GET", "/api/auth/ok"))

    assert_equal 200, status
    assert_equal "application/json", headers["content-type"]
    assert_equal({ok: true}, JSON.parse(body.join, symbolize_names: true))
  end

  def test_router_supports_params_and_method_checks
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            user: BetterAuth::Endpoint.new(path: "/users/:id", method: "GET") do |ctx|
              {id: ctx.params[:id]}
            end
          }
        }
      ]
    )

    status, _headers, body = auth.call(rack_env("GET", "/api/auth/users/user-1"))
    assert_equal 200, status
    assert_equal({id: "user-1"}, JSON.parse(body.join, symbolize_names: true))

    status, headers, _body = auth.call(rack_env("POST", "/api/auth/users/user-1"))
    assert_equal 405, status
    assert_equal "GET", headers["allow"]
  end

  def test_trailing_slash_behavior_matches_option
    default_auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    tolerant_auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      advanced: {skip_trailing_slashes: true}
    )

    assert_equal 404, default_auth.call(rack_env("GET", "/api/auth/ok/")).first
    assert_equal 200, tolerant_auth.call(rack_env("GET", "/api/auth/ok/")).first
  end

  def test_disabled_paths_are_normalized_and_blocked
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      disabled_paths: ["/blocked"],
      plugins: [
        {
          id: "test",
          endpoints: {
            blocked: BetterAuth::Endpoint.new(path: "/blocked", method: "POST") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 404, auth.call(rack_env("POST", "/api/auth/blocked")).first
    assert_equal 404, auth.call(rack_env("POST", "/api/auth/blocked%2F")).first
  end

  def test_plugin_request_and_response_chain_runs_around_endpoint
    order = []
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "a",
          on_request: lambda do |request, _ctx|
            order << "a"
            request.env["HTTP_X_FROM_A"] = "yes"
            {request: request}
          end,
          on_response: lambda do |response, _ctx|
            order << "a-response"
            response[1]["x-after-a"] = "yes"
            {response: response}
          end
        },
        {
          id: "b",
          endpoints: {
            chain: BetterAuth::Endpoint.new(path: "/chain", method: "GET") do |ctx|
              {from_a: ctx.headers["x-from-a"]}
            end
          },
          on_request: lambda do |_request, _ctx|
            order << "b"
            nil
          end
        }
      ]
    )

    status, headers, body = auth.call(rack_env("GET", "/api/auth/chain"))

    assert_equal 200, status
    assert_equal ["a", "b", "a-response"], order
    assert_equal "yes", headers["x-after-a"]
    assert_equal({from_a: "yes"}, JSON.parse(body.join, symbolize_names: true))
  end

  def test_rack_requests_run_endpoint_hooks_like_direct_api
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            echo: BetterAuth::Endpoint.new(path: "/echo", method: "GET") do |ctx|
              {message: ctx.query["message"] || ctx.query[:message] || "endpoint"}
            end
          },
          hooks: {
            after: [
              {
                matcher: ->(ctx) { ctx.path == "/echo" },
                handler: ->(_ctx) { {message: "after"} }
              }
            ]
          }
        }
      ],
      hooks: {
        before: lambda do |ctx|
          next unless ctx.path == "/echo"

          {context: {query: {"message" => "before"}}}
        end
      }
    )

    status, _headers, body = auth.call(rack_env("GET", "/api/auth/echo"))

    assert_equal 200, status
    assert_equal({message: "after"}, JSON.parse(body.join, symbolize_names: true))
  end

  def test_rack_before_hook_can_short_circuit
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            blocked: BetterAuth::Endpoint.new(path: "/blocked", method: "GET") { {ok: true} }
          }
        }
      ],
      hooks: {
        before: ->(_ctx) { {blocked: true} }
      }
    )

    status, _headers, body = auth.call(rack_env("GET", "/api/auth/blocked"))

    assert_equal 200, status
    assert_equal({blocked: true}, JSON.parse(body.join, symbolize_names: true))
  end

  def test_rack_api_errors_keep_error_status_and_body
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

    status, _headers, body = auth.call(rack_env("GET", "/api/auth/fail"))

    assert_equal 403, status
    assert_equal({code: "FORBIDDEN", message: "Blocked"}, JSON.parse(body.join, symbolize_names: true))
  end

  def test_on_response_wraps_early_on_request_responses
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "early",
          endpoints: {
            blocked: BetterAuth::Endpoint.new(path: "/blocked", method: "GET") { {ok: true} }
          },
          on_request: ->(_request, _ctx) { {response: [403, {"content-type" => "text/plain"}, ["blocked"]]} },
          on_response: lambda do |response, _ctx|
            response[1]["x-wrapped"] = "yes"
            {response: response}
          end
        }
      ]
    )

    status, headers, body = auth.call(rack_env("GET", "/api/auth/blocked"))

    assert_equal 403, status
    assert_equal "yes", headers["x-wrapped"]
    assert_equal ["blocked"], body
  end

  def test_origin_check_validates_callbacks_origins_and_fetch_metadata
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "test",
          endpoints: {
            post: BetterAuth::Endpoint.new(path: "/post", method: "POST") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 403, auth.call(rack_env("POST", "/api/auth/post", body: {"callbackURL" => "https://evil.com"})).first
    assert_equal 403, auth.call(rack_env("POST", "/api/auth/post", headers: {"HTTP_ORIGIN" => "https://evil.com", "HTTP_COOKIE" => "session=1"})).first
    assert_equal 200, auth.call(rack_env("POST", "/api/auth/post", headers: {"HTTP_ORIGIN" => "https://evil.com"})).first

    status, _headers, body = auth.call(
      rack_env(
        "POST",
        "/api/auth/post",
        headers: {
          "HTTP_ORIGIN" => "https://evil.com",
          "HTTP_SEC_FETCH_SITE" => "cross-site",
          "HTTP_SEC_FETCH_MODE" => "navigate",
          "HTTP_SEC_FETCH_DEST" => "document"
        }
      )
    )
    assert_equal 403, status
    assert_equal "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
      JSON.parse(body.join)["message"]
  end

  def test_origin_check_disable_flags_match_upstream_split
    endpoint_plugin = {
      id: "test",
      endpoints: {
        post: BetterAuth::Endpoint.new(path: "/post", method: "POST") { {ok: true} }
      }
    }

    csrf_disabled = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      advanced: {disable_csrf_check: true, disable_origin_check: false},
      plugins: [endpoint_plugin]
    )
    origin_disabled = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      advanced: {disable_origin_check: true},
      plugins: [endpoint_plugin]
    )

    assert_equal 200, csrf_disabled.call(rack_env("POST", "/api/auth/post", headers: {"HTTP_ORIGIN" => "https://evil.com", "HTTP_COOKIE" => "session=1"})).first
    assert_equal 403, csrf_disabled.call(rack_env("POST", "/api/auth/post", body: {"callbackURL" => "https://evil.com"})).first
    assert_equal 200, origin_disabled.call(rack_env("POST", "/api/auth/post", body: {"callbackURL" => "https://evil.com"})).first
  end

  def test_rate_limit_runs_after_plugin_on_request
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      rate_limit: {enabled: true, window: 60, max: 1},
      plugins: [
        {
          id: "test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/limited")).first
  end

  def test_rate_limit_uses_custom_storage_with_upstream_retry_header
    storage = RateLimitStorage.new
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      rate_limit: {enabled: true, window: 60, max: 1, custom_storage: storage},
      plugins: [
        {
          id: "test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
    status, headers, body = auth.call(rack_env("GET", "/api/auth/limited"))

    assert_equal 429, status
    assert_match(/\A\d+\z/, headers["x-retry-after"])
    assert_equal({"message" => "Too many requests. Please try again later."}, JSON.parse(body.join))
    assert_equal ["127.0.0.1|/limited"], storage.keys
  end

  def test_rate_limit_can_use_secondary_storage_with_ttl
    storage = SecondaryStorage.new
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      secondary_storage: storage,
      rate_limit: {enabled: true, window: 60, max: 1, storage: "secondary-storage"},
      plugins: [
        {
          id: "test",
          endpoints: {
            limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert_equal 200, auth.call(rack_env("GET", "/api/auth/limited")).first
    assert_equal 429, auth.call(rack_env("GET", "/api/auth/limited")).first
    assert_equal 60, storage.ttls["127.0.0.1|/limited"]
  end

  def test_trusted_proxy_headers_reject_malformed_forwarded_values
    captured = []
    auth = BetterAuth.auth(
      secret: SECRET,
      advanced: {trusted_proxy_headers: true},
      hooks: {
        before: lambda do |ctx|
          captured << ctx.context.base_url
          nil
        end
      }
    )

    auth.call(rack_env("GET", "/api/auth/ok", headers: {"HTTP_X_FORWARDED_HOST" => "example.com:8080", "HTTP_X_FORWARDED_PROTO" => "https"}))
    auth.call(rack_env("GET", "/api/auth/ok", headers: {"HTTP_X_FORWARDED_HOST" => "evil.com:99999", "HTTP_X_FORWARDED_PROTO" => "http"}))
    auth.call(rack_env("GET", "/api/auth/ok", headers: {"HTTP_X_FORWARDED_HOST" => "<script>alert(1)</script>", "HTTP_X_FORWARDED_PROTO" => "http"}))
    auth.call(rack_env("GET", "/api/auth/ok", headers: {"HTTP_X_FORWARDED_HOST" => "example.com", "HTTP_X_FORWARDED_PROTO" => "javascript"}))

    assert_equal "https://example.com:8080/api/auth", captured[0]
    assert_equal "http://localhost:3000/api/auth", captured[1]
    assert_equal "http://localhost:3000/api/auth", captured[2]
    assert_equal "http://localhost:3000/api/auth", captured[3]
  end

  def test_endpoint_conflict_logging
    messages = []

    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      logger: ->(level, message) { messages << [level, message] },
      plugins: [
        {
          id: "one",
          endpoints: {
            shared: BetterAuth::Endpoint.new(path: "/shared", method: "GET") { {ok: true} }
          }
        },
        {
          id: "two",
          endpoints: {
            shared: BetterAuth::Endpoint.new(path: "/shared", method: "GET") { {ok: true} }
          }
        }
      ]
    )

    assert messages.any? { |level, message| level == :error && message.include?("Endpoint path conflicts detected") }
    assert messages.any? { |_level, message| message.include?("\"/shared\" [GET] used by plugins: one, two") }
  end

  private

  def rack_env(method, path, body: nil, headers: {})
    payload = body ? JSON.generate(body) : ""
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path,
      "QUERY_STRING" => "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(payload),
      "CONTENT_TYPE" => body ? "application/json" : nil,
      "CONTENT_LENGTH" => payload.bytesize.to_s
    }.merge(headers).compact
  end

  class RateLimitStorage
    attr_reader :data

    def initialize
      @data = {}
    end

    def get(key)
      data[key]
    end

    def set(key, value, ttl: nil, update: false)
      data[key] = value.merge(ttl: ttl, update: update)
    end

    def keys
      data.keys
    end
  end

  class SecondaryStorage
    attr_reader :data, :ttls

    def initialize
      @data = {}
      @ttls = {}
    end

    def get(key)
      data[key]
    end

    def set(key, value, ttl)
      data[key] = value
      ttls[key] = ttl
    end
  end
end
