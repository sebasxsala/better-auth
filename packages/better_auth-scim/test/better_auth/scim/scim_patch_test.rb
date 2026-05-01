# frozen_string_literal: true

require_relative "../scim_test_helper"

class BetterAuthPluginsScimPatchTest < Minitest::Test
  include SCIMTestHelper

  def test_scim_patch_matches_upstream_supported_operations
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)
    created = auth.api.create_scim_user(
      headers: headers,
      body: {userName: "patch@example.com", externalId: "external-1", name: {givenName: "Patch", familyName: "User"}}
    )

    auth.api.patch_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [
          {op: "replace", path: "/userName", value: "patched@example.com"},
          {op: "add", path: "/externalId", value: "external-2"},
          {op: "REPLACE", path: "/name/givenName", value: "Patched"},
          {op: "ADD", path: "/name/familyName", value: "Person"}
        ]
      },
      return_status: true
    )
    patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "patched@example.com", patched.fetch(:userName)
    assert_equal "external-2", patched.fetch(:externalId)
    assert_equal "Patched Person", patched.fetch(:displayName)

    auth.api.patch_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [
          {op: "replace", path: "name", value: {givenName: "Nested", familyName: "Name"}},
          {op: "add", path: "name", value: {givenName: "Nested", familyName: "Name"}},
          {value: {userName: "object@example.com", externalId: "external-3"}}
        ]
      },
      return_status: true
    )
    object_patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "object@example.com", object_patched.fetch(:userName)
    assert_equal "external-3", object_patched.fetch(:externalId)
    assert_equal "Nested Name", object_patched.fetch(:displayName)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: "remove", path: "/externalId"}]}
      )
    end
    assert_equal 400, error.status_code
    assert_equal "No valid fields to update", error.message

    duplicate_add = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: "add", path: "/name/formatted", value: "Nested Name"}]}
      )
    end
    assert_equal 400, duplicate_add.status_code
    assert_equal "No valid fields to update", duplicate_add.message
  end

  def test_scim_patch_supports_dot_name_paths_and_rejects_noop_patch
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)
    created = auth.api.create_scim_user(headers: headers, body: {userName: "patch-name@example.com", name: {formatted: "Patch User"}})

    auth.api.patch_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [
          {op: "replace", path: "name.givenName", value: "Given"},
          {op: "replace", path: "name.familyName", value: "Family"}
        ]
      },
      return_status: true
    )
    patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "Given Family", patched.fetch(:displayName)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: "replace", path: "unknown", value: "ignored"}]}
      )
    end
    assert_equal 400, error.status_code
    assert_equal "No valid fields to update", error.message

    invalid_op = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: "invalid", path: "userName", value: "ignored@example.com"}]}
      )
    end
    assert_equal 400, invalid_op.status_code
    assert_equal "Invalid SCIM patch operation", invalid_op.message

    non_string_op = assert_raises(BetterAuth::APIError) do
      auth.api.patch_scim_user(
        headers: headers,
        params: {userId: created.fetch(:id)},
        body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: 1, path: "userName", value: "ignored@example.com"}]}
      )
    end
    assert_equal 400, non_string_op.status_code
    assert_equal "Invalid SCIM patch operation", non_string_op.message
  end
end
