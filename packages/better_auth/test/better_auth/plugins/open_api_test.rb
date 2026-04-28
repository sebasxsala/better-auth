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

    assert_equal "3.1.1", schema[:openapi]
    assert_equal "Better Auth", schema.dig(:info, :title)
    assert_equal "API Reference for your Better Auth Instance", schema.dig(:info, :description)
    assert_equal "1.1.0", schema.dig(:info, :version)
    assert_equal({type: "string"}, schema.dig(:components, :schemas, :User, :properties, :id))
    assert_equal "user", schema.dig(:components, :schemas, :User, :properties, :role, :default)
    assert_includes schema.dig(:components, :schemas, :User, :required), "role"
    assert_includes schema[:paths].keys, "/sign-in/social"
    assert_includes schema[:paths].keys, "/token"
    refute_includes schema[:paths].keys, "/open-api/generate-schema"
    assert_equal [{url: "http://localhost:3000/api/auth"}], schema[:servers]
    assert_equal(
      {
        apiKeyCookie: {
          type: "apiKey",
          in: "cookie",
          name: "apiKeyCookie",
          description: "API Key authentication via cookie"
        },
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          description: "Bearer token authentication"
        }
      },
      schema.dig(:components, :securitySchemes)
    )
  end

  def test_open_api_model_schema_matches_upstream_field_metadata
    auth = build_auth(plugins: [BetterAuth::Plugins.open_api])

    schema = auth.api.generate_open_api_schema

    assert_equal(
      {type: "boolean", default: false, readOnly: true},
      schema.dig(:components, :schemas, :User, :properties, :emailVerified)
    )
    assert_equal(
      {type: "string", format: "date-time", default: "Generated at runtime"},
      schema.dig(:components, :schemas, :User, :properties, :createdAt)
    )
    refute_includes schema.dig(:components, :schemas, :User, :required), "emailVerified"
    assert_includes schema.dig(:components, :schemas, :Session, :required), "token"
  end

  def test_open_api_uses_upstream_31_nullable_request_body_shapes
    auth = build_auth(plugins: [BetterAuth::Plugins.open_api])

    schema = auth.api.generate_open_api_schema
    social_body = schema.dig(:paths, "/sign-in/social", :post, :requestBody, :content, "application/json", :schema)
    id_token = social_body.dig(:properties, :idToken)

    assert_equal ["object", "null"], id_token[:type]
    assert_equal "string", id_token.dig(:properties, :token, :type)
    assert_equal ["string", "null"], id_token.dig(:properties, :accessToken, :type)
    assert_equal ["string", "null"], id_token.dig(:properties, :refreshToken, :type)
    assert_nil id_token.dig(:properties, :accessToken, :nullable)
    assert_nil id_token[:nullable]
    assert_includes id_token[:required], "token"
    refute_includes social_body.fetch(:required), "idToken"
  end

  def test_open_api_unwraps_default_values_and_boolean_types
    auth = build_auth(plugins: [BetterAuth::Plugins.open_api])

    schema = auth.api.generate_open_api_schema
    sign_in = schema.dig(:paths, "/sign-in/email", :post, :requestBody, :content, "application/json", :schema, :properties)
    sign_up = schema.dig(:paths, "/sign-up/email", :post, :requestBody, :content, "application/json", :schema, :properties)

    assert_equal ["boolean", "null"], sign_in.dig(:rememberMe, :type)
    assert_equal true, sign_in.dig(:rememberMe, :default)
    assert_equal "boolean", sign_up.dig(:rememberMe, :type)
    refute sign_up.fetch(:rememberMe).key?(:default)
  end

  def test_open_api_adds_default_operation_metadata_and_path_parameters
    auth = build_auth(plugins: [BetterAuth::Plugins.open_api])

    schema = auth.api.generate_open_api_schema
    callback = schema.dig(:paths, "/callback/{providerId}", :get)

    assert callback
    assert_equal ["Default"], callback[:tags]
    assert_equal [{bearerAuth: []}], callback[:security]
    assert_equal [], callback[:parameters]
    assert_includes callback[:responses].keys, "400"
    assert_equal(
      "Bad Request. Usually due to missing parameters, or invalid parameters.",
      callback.dig(:responses, "400", :description)
    )
  end

  def test_open_api_reference_returns_html
    auth = build_auth(plugins: [BetterAuth::Plugins.open_api(theme: "moon", nonce: "abc123")])

    status, headers, body = auth.api.open_api_reference(as_response: true)

    assert_equal 200, status
    assert_equal "text/html", headers["content-type"]
    assert_includes body.join, "Scalar API Reference"
    assert_includes body.join, "nonce=\"abc123\""
  end

  def test_open_api_reference_can_be_disabled
    auth = build_auth(plugins: [BetterAuth::Plugins.open_api(disable_default_reference: true)])

    error = assert_raises(BetterAuth::APIError) do
      auth.api.open_api_reference
    end

    assert_equal 404, error.status_code
  end

  def test_open_api_respects_disabled_paths
    auth = build_auth(
      disabled_paths: ["/sign-in/social"],
      plugins: [BetterAuth::Plugins.open_api]
    )

    schema = auth.api.generate_open_api_schema

    refute_includes schema[:paths].keys, "/sign-in/social"
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end
end
