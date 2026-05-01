# frozen_string_literal: true

require_relative "../scim_test_helper"

class BetterAuthPluginsScimTest < Minitest::Test
  include SCIMTestHelper

  def test_scim_plugin_surface_exposes_version_client_and_hidden_metadata
    plugin = BetterAuth::Plugins.scim

    assert_equal BetterAuth::SCIM::VERSION, plugin.version
    assert_equal "scim-client", plugin.client.fetch("id")
    assert_equal BetterAuth::SCIM::VERSION, plugin.client.fetch("version")
    assert_equal "scim", plugin.client.fetch("serverPluginId")
    assert_equal true, plugin.endpoints.fetch(:create_scim_user).metadata.fetch(:hide)
    assert_equal "Create SCIM user.", plugin.endpoints.fetch(:create_scim_user).metadata.fetch(:openapi).fetch(:summary)
    refute plugin.endpoints.fetch(:generate_scim_token).metadata.fetch(:hide, false)

    auth = build_auth(plugins: [BetterAuth::Plugins.scim, BetterAuth::Plugins.open_api])
    paths = auth.api.generate_open_api_schema.fetch(:paths)

    assert paths.key?("/scim/generate-token")
    refute paths.key?("/scim/v2/Users")
    refute paths.key?("/scim/v2/ServiceProviderConfig")
  end

  def test_scim_metadata_endpoints_match_scim_v2_shapes
    auth = build_auth

    config = auth.api.get_scim_service_provider_config
    assert_equal ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"], config.fetch(:schemas)
    assert_equal true, config.fetch(:patch).fetch(:supported)
    assert_equal({supported: false}, config.fetch(:bulk))
    assert_equal({supported: true}, config.fetch(:filter))
    assert_equal({resourceType: "ServiceProviderConfig"}, config.fetch(:meta))
    assert_equal true, config.fetch(:authenticationSchemes).first.fetch(:primary)

    schemas = auth.api.get_scim_schemas
    assert_equal ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], schemas.fetch(:schemas)
    assert_equal 1, schemas.fetch(:itemsPerPage)
    assert_equal 1, schemas.fetch(:startIndex)
    assert_operator schemas.fetch(:Resources).length, :>=, 1

    user_schema = auth.api.get_scim_schema(params: {schemaId: "urn:ietf:params:scim:schemas:core:2.0:User"})
    assert_equal "User", user_schema.fetch(:name)
    assert user_schema.fetch(:attributes).any? { |attribute| attribute.fetch(:name) == "emails" }

    resource_types = auth.api.get_scim_resource_types
    assert_equal ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], resource_types.fetch(:schemas)
    assert_equal 1, resource_types.fetch(:itemsPerPage)
    assert_equal 1, resource_types.fetch(:startIndex)
    assert_equal ["User"], resource_types.fetch(:Resources).map { |resource| resource.fetch(:name) }

    resource_type = auth.api.get_scim_resource_type(params: {resourceTypeId: "User"})
    assert_equal "/Users", resource_type.fetch(:endpoint)
    assert_equal "ResourceType", resource_type.fetch(:meta).fetch(:resourceType)

    schema_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_schema(params: {schemaId: "unknown"})
    end
    assert_equal 404, schema_error.status_code
    assert_equal ["urn:ietf:params:scim:api:messages:2.0:Error"], schema_error.body.fetch(:schemas)

    resource_type_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_resource_type(params: {resourceTypeId: "unknown"})
    end
    assert_equal 404, resource_type_error.status_code
    assert_equal ["urn:ietf:params:scim:api:messages:2.0:Error"], resource_type_error.body.fetch(:schemas)
  end

  def test_scim_errors_use_scim_error_shape
    auth = build_auth

    status, _headers, body = auth.api.create_scim_user(as_response: true, body: {userName: "anon@example.com"})
    error = JSON.parse(body.join)

    assert_equal 401, status
    assert_equal ["urn:ietf:params:scim:api:messages:2.0:Error"], error.fetch("schemas")
    assert_equal "401", error.fetch("status")
    assert_equal "SCIM token is required", error.fetch("detail")
  end

  def test_scim_validates_user_and_patch_bodies
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)

    missing_user_name = assert_raises(BetterAuth::APIError) do
      auth.api.create_scim_user(headers: headers, body: {emails: [{value: "valid@example.com"}]})
    end
    assert_equal 400, missing_user_name.status_code
    assert_equal "Validation Error", missing_user_name.message

    invalid_email = assert_raises(BetterAuth::APIError) do
      auth.api.create_scim_user(headers: headers, body: {userName: "username", emails: [{value: "not-an-email"}]})
    end
    assert_equal 400, invalid_email.status_code
    assert_equal "Validation Error", invalid_email.message

    [
      {userName: 123},
      {userName: "username", externalId: 1},
      {userName: "username", name: "Invalid Name"},
      {userName: "username", name: {givenName: 1}},
      {userName: "username", emails: ["invalid"]},
      {userName: "username", emails: [{value: "valid@example.com", primary: "yes"}]}
    ].each do |body|
      error = assert_raises(BetterAuth::APIError) do
        auth.api.create_scim_user(headers: headers, body: body)
      end
      assert_equal 400, error.status_code
      assert_equal "Validation Error", error.message
    end

    created = auth.api.create_scim_user(headers: headers, body: {userName: "patch-validation@example.com"})
    invalid_patch_schema = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["wrong"], Operations: [{op: "replace", path: "userName", value: "ignored@example.com"}]}
      )
    end
    assert_equal 400, invalid_patch_schema.status_code
    assert_equal "Invalid schemas for PatchOp", invalid_patch_schema.message
  end

  def test_scim_create_user_sets_location_and_accepts_scim_json
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)

    status, headers, body = auth.api.create_scim_user(
      as_response: true,
      headers: bearer(token).merge("content-type" => "application/scim+json"),
      body: {userName: "location@example.com"}
    )
    created = JSON.parse(body.join)

    assert_equal 201, status
    assert_match %r{/scim/v2/Users/#{created.fetch("id")}\z}, headers.fetch("location")
    assert_equal ["urn:ietf:params:scim:schemas:core:2.0:User"], created.fetch("schemas")
    assert_equal true, created.fetch("active")
    assert_equal "location@example.com", created.fetch("displayName")
    assert_equal "location@example.com", created.fetch("name").fetch("formatted")
    assert_equal [{"primary" => true, "value" => "location@example.com"}], created.fetch("emails")
    assert_equal "User", created.fetch("meta").fetch("resourceType")

    response = Rack::MockRequest.new(auth).post(
      "/api/auth/scim/v2/Users",
      "CONTENT_TYPE" => "application/scim+json",
      "HTTP_AUTHORIZATION" => "Bearer #{token}",
      :input => JSON.generate({userName: "rack-location@example.com"})
    )
    rack_created = JSON.parse(response.body)

    assert_equal 201, response.status
    assert_equal "rack-location@example.com", rack_created.fetch("userName")

    upper = auth.api.create_scim_user(headers: bearer(token), body: {userName: "Upper@Example.com"})
    assert_equal "upper@example.com", upper.fetch(:userName)
    assert_equal "upper@example.com", upper.fetch(:externalId)
  end

  def test_scim_create_user_email_selection_duplicate_and_existing_user
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)

    primary = auth.api.create_scim_user(
      headers: headers,
      body: {userName: "username", name: {formatted: "Primary User"}, emails: [{value: "secondary@example.com"}, {value: "primary@example.com", primary: true}]}
    )
    assert_equal "primary@example.com", primary.fetch(:userName)
    assert_equal "username", primary.fetch(:externalId)

    first = auth.api.create_scim_user(
      headers: headers,
      body: {userName: "first-username", emails: [{value: "first@example.com"}, {value: "second@example.com"}]}
    )
    assert_equal "first@example.com", first.fetch(:userName)

    auth.context.internal_adapter.create_user(email: "existing@example.com", name: "Existing User")
    existing = auth.api.create_scim_user(headers: headers, body: {userName: "external-existing", emails: [{value: "existing@example.com"}]})
    assert_equal "Existing User", existing.fetch(:displayName)
    assert_equal "external-existing", existing.fetch(:externalId)

    assert_raises(BetterAuth::APIError) do
      auth.api.create_scim_user(headers: headers, body: {userName: "external-existing"})
    end
  end

  def test_scim_update_and_patch_reject_anonymous_and_missing_users
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)

    assert_equal 401, auth.api.update_scim_user(as_response: true, params: {userId: "missing"}, body: {userName: "anon@example.com"}).first
    assert_equal 401, auth.api.patch_scim_user(as_response: true, params: {userId: "missing"}, body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: []}).first

    missing_update = assert_raises(BetterAuth::APIError) do
      auth.api.update_scim_user(headers: headers, params: {userId: "missing"}, body: {userName: "missing@example.com"})
    end
    assert_equal 404, missing_update.status_code

    missing_patch = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(headers: headers, params: {userId: "missing"}, body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: "replace", path: "userName", value: "missing@example.com"}]})
    end
    assert_equal 404, missing_patch.status_code
  end
end
