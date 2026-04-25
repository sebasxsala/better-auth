# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthAuthTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_auth_returns_public_api_shape
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    assert_instance_of BetterAuth::Auth, auth
    assert_respond_to auth, :handler
    assert_respond_to auth, :api
    assert_respond_to auth, :options
    assert_respond_to auth, :context
    assert_respond_to auth, :error_codes
    assert_equal "/api/auth", auth.options.base_path
    assert_equal "http://localhost:3000/api/auth", auth.context.base_url
  end

  def test_auth_is_rack_callable_alias_to_handler
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    status, headers, body = auth.call(
      "REQUEST_METHOD" => "GET",
      "PATH_INFO" => "/api/auth/unknown",
      "rack.input" => StringIO.new
    )

    assert_equal 404, status
    assert_equal "application/json", headers["content-type"]
    assert_equal ["{\"error\":\"Not Found\"}"], body
  end

  def test_plugin_error_codes_merge_with_base_error_codes
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      plugins: [
        {
          id: "custom-plugin",
          error_codes: {
            "CUSTOM_ERROR" => "Custom error message"
          }
        }
      ]
    )

    assert_equal "User not found", auth.error_codes["USER_NOT_FOUND"]
    assert_equal "Custom error message", auth.error_codes["CUSTOM_ERROR"]
  end
end
