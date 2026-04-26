# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsOpenAPITest < Minitest::Test
  SECRET = "phase-seven-secret-with-enough-entropy-123"

  def test_open_api_generates_schema_from_routes_and_models
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.jwt,
        BetterAuth::Plugins.open_api
      ],
      user: {
        additional_fields: {
          role: {type: "string", required: true, default_value: "user"},
          preferences: {type: "string", required: false}
        }
      }
    )

    schema = auth.api.generate_open_api_schema

    assert_equal "3.1.0", schema[:openapi]
    assert_equal({type: "string"}, schema.dig(:components, :schemas, :User, :properties, :id))
    assert_equal "user", schema.dig(:components, :schemas, :User, :properties, :role, :default)
    assert_includes schema.dig(:components, :schemas, :User, :required), "role"
    assert_includes schema[:paths].keys, "/sign-in/social"
    assert_includes schema[:paths].keys, "/token"
  end

  def test_open_api_reference_returns_html
    auth = build_auth(plugins: [BetterAuth::Plugins.open_api(theme: "moon", nonce: "abc123")])

    status, headers, body = auth.api.open_api_reference(as_response: true)

    assert_equal 200, status
    assert_equal "text/html", headers["content-type"]
    assert_includes body.join, "Scalar API Reference"
    assert_includes body.join, "nonce=\"abc123\""
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end
end
