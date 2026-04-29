# frozen_string_literal: true

require "json"
require "rack/mock"
require_relative "../test_helper"

class BetterAuthPluginsSCIMTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

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

  def test_generates_plain_hashed_and_custom_scim_tokens
    plain = build_auth(store_scim_token: "plain")
    plain_cookie = sign_up_cookie(plain)
    plain_token = plain.api.generate_scim_token(headers: {"cookie" => plain_cookie}, body: {providerId: "plain-provider"})
    assert_kind_of String, plain_token.fetch(:scimToken)
    assert plain.api.create_scim_user(headers: bearer(plain_token.fetch(:scimToken)), body: {userName: "plain@example.com"})

    hashed = build_auth(store_scim_token: "hashed")
    hashed_cookie = sign_up_cookie(hashed)
    hashed_token = hashed.api.generate_scim_token(headers: {"cookie" => hashed_cookie}, body: {providerId: "hashed-provider"})
    stored = hashed.context.adapter.find_one(model: "scimProvider", where: [{field: "providerId", value: "hashed-provider"}])
    refute_equal hashed_token.fetch(:scimToken), stored.fetch("scimToken")
    assert_match(/\A[A-Za-z0-9_-]{43}\z/, stored.fetch("scimToken"))
    assert hashed.api.create_scim_user(headers: bearer(hashed_token.fetch(:scimToken)), body: {userName: "hashed@example.com"})

    custom = build_auth(store_scim_token: {hash: ->(token) { "custom:#{token}" }})
    custom_cookie = sign_up_cookie(custom)
    custom_token = custom.api.generate_scim_token(headers: {"cookie" => custom_cookie}, body: {providerId: "custom-provider"})
    assert custom.api.create_scim_user(headers: bearer(custom_token.fetch(:scimToken)), body: {userName: "custom@example.com"})
  end

  def test_scim_tokens_use_upstream_envelope_storage_and_encrypted_modes
    encrypted = build_auth(store_scim_token: "encrypted")
    encrypted_cookie = sign_up_cookie(encrypted)
    encrypted_token = encrypted.api.generate_scim_token(headers: {"cookie" => encrypted_cookie}, body: {providerId: "encrypted-provider"})
    stored = encrypted.context.adapter.find_one(model: "scimProvider", where: [{field: "providerId", value: "encrypted-provider"}])

    refute_includes encrypted_token.fetch(:scimToken), "encrypted-provider"
    refute_equal encrypted_token.fetch(:scimToken), stored.fetch("scimToken")
    assert encrypted.api.create_scim_user(headers: bearer(encrypted_token.fetch(:scimToken)), body: {userName: "encrypted@example.com"})

    custom = build_auth(store_scim_token: {encrypt: ->(token) { "enc:#{token}" }, decrypt: ->(token) { token.delete_prefix("enc:") }})
    custom_cookie = sign_up_cookie(custom)
    custom_token = custom.api.generate_scim_token(headers: {"cookie" => custom_cookie}, body: {providerId: "custom-encrypted-provider"})
    assert custom.api.create_scim_user(headers: bearer(custom_token.fetch(:scimToken)), body: {userName: "custom-encrypted@example.com"})
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
      {userName: "username", externalId: 1},
      {userName: "username", name: "Invalid Name"},
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

  def test_scim_user_crud_filter_patch_and_delete
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)

    created = auth.api.create_scim_user(
      headers: headers,
      body: {
        userName: "scim@example.com",
        externalId: "external-1",
        name: {givenName: "SCIM", familyName: "User"}
      }
    )
    assert_equal "scim@example.com", created.fetch(:userName)
    assert_equal "external-1", created.fetch(:externalId)
    assert_equal true, created.fetch(:active)
    assert created.fetch(:meta).fetch(:created)
    assert created.fetch(:meta).fetch(:lastModified)

    listed = auth.api.list_scim_users(headers: headers, query: {filter: 'userName eq "SCIM@example.com"'})
    assert_equal 1, listed.fetch(:totalResults)

    fetched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "SCIM User", fetched.fetch(:displayName)

    updated = auth.api.update_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {userName: "updated-username", externalId: "external-2", name: {formatted: "Updated User"}, emails: [{value: "updated@example.com"}]}
    )
    assert_equal "updated@example.com", updated.fetch(:userName)
    assert_equal "external-2", updated.fetch(:externalId)
    assert_equal "Updated User", updated.fetch(:displayName)

    patch_status = auth.api.patch_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{op: "replace", path: "userName", value: "patched@example.com"}]},
      return_status: true
    )
    assert_equal 204, patch_status.fetch(:status)
    patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "patched@example.com", patched.fetch(:userName)
    assert_equal true, patched.fetch(:active)

    deleted = auth.api.delete_scim_user(headers: headers, params: {userId: created.fetch(:id)}, return_status: true)
    assert_equal 204, deleted.fetch(:status)
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

  def test_scim_filters_only_user_name_and_rejects_unsupported_filters
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)
    auth.api.create_scim_user(headers: headers, body: {userName: "a@example.com", externalId: "external-a"})
    auth.api.create_scim_user(headers: headers, body: {userName: "b@example.com", externalId: "external-b"})

    listed = auth.api.list_scim_users(headers: headers, query: {filter: 'userName eq "B@example.com"'})
    assert_equal 1, listed.fetch(:totalResults)
    assert_equal "b@example.com", listed.fetch(:Resources).first.fetch(:userName)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.list_scim_users(headers: headers, query: {filter: 'userName co "example.com"'})
    end
    assert_equal 400, error.status_code
    assert_equal 'The operator "co" is not supported', error.message

    attribute_error = assert_raises(BetterAuth::APIError) do
      auth.api.list_scim_users(headers: headers, query: {filter: 'externalId eq "external-b"'})
    end
    assert_equal 400, attribute_error.status_code
    assert_equal "The attribute \"externalId\" is not supported", attribute_error.message

    %w[ne co sw ew pr].each do |operator|
      error = assert_raises(BetterAuth::APIError) do
        auth.api.list_scim_users(headers: headers, query: {filter: %(userName #{operator} "b@example.com")})
      end
      assert_equal 400, error.status_code
      assert_equal %(The operator "#{operator}" is not supported), error.message
    end
  end

  def test_scim_requires_org_plugin_and_membership_for_org_tokens
    no_org = build_auth
    no_org_cookie = sign_up_cookie(no_org)
    error = assert_raises(BetterAuth::APIError) do
      no_org.api.generate_scim_token(headers: {"cookie" => no_org_cookie}, body: {providerId: "okta", organizationId: "org-1"})
    end
    assert_equal 400, error.status_code
    assert_equal "Restricting a token to an organization requires the organization plugin", error.message

    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    org = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "SCIM Org", slug: "scim-org"})
    second_cookie = sign_up_cookie(auth, "other@example.com")

    forbidden = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => second_cookie}, body: {providerId: "okta", organizationId: org.fetch("id")})
    end
    assert_equal 403, forbidden.status_code
    assert_equal "You are not a member of the organization", forbidden.message

    token = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "okta", organizationId: org.fetch("id")})
    assert_kind_of String, token.fetch(:scimToken)
  end

  def test_scim_default_provider_and_invalid_tokens
    scim_token = Base64.urlsafe_encode64("the-scim-token:the-scim-provider", padding: false)
    auth = build_auth(default_scim: [{providerId: "the-scim-provider", scimToken: "the-scim-token"}])

    created = auth.api.create_scim_user(headers: bearer(scim_token), body: {userName: "default@example.com"})
    assert_equal created, auth.api.get_scim_user(headers: bearer(scim_token), params: {userId: created.fetch(:id)})
    assert_equal [created.fetch(:id)], auth.api.list_scim_users(headers: bearer(scim_token)).fetch(:Resources).map { |user| user.fetch(:id) }
    updated = auth.api.update_scim_user(headers: bearer(scim_token), params: {userId: created.fetch(:id)}, body: {userName: "updated-default@example.com"})
    assert_equal "updated-default@example.com", updated.fetch(:userName)
    assert_equal 204, auth.api.delete_scim_user(headers: bearer(scim_token), params: {userId: created.fetch(:id)}, return_status: true).fetch(:status)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_scim_user(headers: bearer("invalid-scim-token"), body: {userName: "bad@example.com"})
    end
    assert_equal 401, error.status_code
    assert_equal "Invalid SCIM token", error.message

    conflicting = build_auth(default_scim: [{providerId: "same-provider", scimToken: "default-token"}])
    cookie = sign_up_cookie(conflicting)
    db_token = conflicting.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "same-provider"}).fetch(:scimToken)
    default_precedence_error = assert_raises(BetterAuth::APIError) do
      conflicting.api.create_scim_user(headers: bearer(db_token), body: {userName: "db-token@example.com"})
    end
    assert_equal 401, default_precedence_error.status_code
  end

  def test_scim_provider_management_roles_ownership_and_hooks
    calls = []
    scim_options = {
      provider_ownership: {enabled: true},
      required_role: ["owner"],
      before_scim_token_generated: ->(payload) { calls << [:before, payload.fetch(:user).fetch("email"), payload.fetch(:scim_token)] },
      after_scim_token_generated: ->(payload) { calls << [:after, payload.fetch(:scim_provider).fetch("providerId"), payload.fetch(:scim_token)] }
    }
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim(scim_options)])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    other_cookie = sign_up_cookie(auth, "other@example.com")
    other_user = auth.api.get_session(headers: {"cookie" => other_cookie}).fetch(:user)

    assert_equal 401, auth.api.generate_scim_token(as_response: true, body: {providerId: "anonymous"}).first
    invalid_provider = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "bad:provider"})
    end
    assert_equal 400, invalid_provider.status_code

    personal_token = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "personal"}).fetch(:scimToken)
    providers = auth.api.list_scim_provider_connections(headers: {"cookie" => owner_cookie}).fetch(:providers)
    assert_equal [{id: providers.first.fetch(:id), providerId: "personal", organizationId: nil}], providers

    forbidden = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_provider_connection(headers: {"cookie" => other_cookie}, query: {providerId: "personal"})
    end
    assert_equal 403, forbidden.status_code
    assert_equal "You must be the owner to access this provider", forbidden.message

    regenerate_forbidden = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => other_cookie}, body: {providerId: "personal"})
    end
    assert_equal 403, regenerate_forbidden.status_code

    org = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "SCIM Org", slug: "scim-org"})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org.fetch("id"), userId: other_user.fetch("id"), role: "member"})
    member_forbidden = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => other_cookie}, body: {providerId: "okta", organizationId: org.fetch("id")})
    end
    assert_equal 403, member_forbidden.status_code
    assert_equal "Insufficient role for this operation", member_forbidden.message

    org_token = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "okta", organizationId: org.fetch("id")}).fetch(:scimToken)
    org_provider = auth.api.get_scim_provider_connection(headers: {"cookie" => owner_cookie}, query: {providerId: "okta"})
    assert_equal({providerId: "okta", organizationId: org.fetch("id")}, org_provider.slice(:providerId, :organizationId))
    assert_equal [:before, "owner@example.com"], calls.first[0, 2]
    assert_equal [:after, "personal"], calls[1][0, 2]

    deleted = auth.api.delete_scim_provider_connection(headers: {"cookie" => owner_cookie}, body: {providerId: "personal"})
    assert_equal true, deleted.fetch(:success)
    assert_raises(BetterAuth::APIError) do
      auth.api.create_scim_user(headers: bearer(personal_token), body: {userName: "invalid@example.com"})
    end
    assert auth.api.create_scim_user(headers: bearer(org_token), body: {userName: "org@example.com"})

    missing_provider = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_provider_connection(headers: {"cookie" => owner_cookie}, query: {providerId: "missing"})
    end
    assert_equal 404, missing_provider.status_code

    missing_delete = assert_raises(BetterAuth::APIError) do
      auth.api.delete_scim_provider_connection(headers: {"cookie" => owner_cookie}, body: {providerId: "missing"})
    end
    assert_equal 404, missing_delete.status_code

    no_org_list = build_auth(provider_ownership: {enabled: true})
    no_org_owner_cookie = sign_up_cookie(no_org_list, "no-org-owner@example.com")
    no_org_list.api.generate_scim_token(headers: {"cookie" => no_org_owner_cookie}, body: {providerId: "standalone"})
    assert_equal ["standalone"], no_org_list.api.list_scim_provider_connections(headers: {"cookie" => no_org_owner_cookie}).fetch(:providers).map { |provider| provider.fetch(:providerId) }

    aborting_auth = build_auth(
      plugins: [
        BetterAuth::Plugins.organization,
        BetterAuth::Plugins.scim(before_scim_token_generated: ->(_payload) { raise BetterAuth::APIError.new("FORBIDDEN", message: "blocked by hook") })
      ]
    )
    abort_cookie = sign_up_cookie(aborting_auth, "abort@example.com")
    hook_error = assert_raises(BetterAuth::APIError) do
      aborting_auth.api.generate_scim_token(headers: {"cookie" => abort_cookie}, body: {providerId: "blocked"})
    end
    assert_equal 403, hook_error.status_code
    assert_equal "blocked by hook", hook_error.message
  end

  def test_scim_provider_management_respects_admin_custom_roles_and_creator_role
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    admin_cookie = sign_up_cookie(auth, "admin@example.com")
    member_cookie = sign_up_cookie(auth, "member@example.com")
    admin_user = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    member_user = auth.api.get_session(headers: {"cookie" => member_cookie}).fetch(:user)
    org = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Roles", slug: "roles"})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org.fetch("id"), userId: admin_user.fetch("id"), role: ["member", "admin"]})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: org.fetch("id"), userId: member_user.fetch("id"), role: "member"})

    token = auth.api.generate_scim_token(headers: {"cookie" => admin_cookie}, body: {providerId: "admin-okta", organizationId: org.fetch("id")})
    assert_kind_of String, token.fetch(:scimToken)
    assert_equal ["admin-okta"], auth.api.list_scim_provider_connections(headers: {"cookie" => admin_cookie}).fetch(:providers).map { |provider| provider.fetch(:providerId) }
    assert_equal [], auth.api.list_scim_provider_connections(headers: {"cookie" => member_cookie}).fetch(:providers)

    owner_only = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim(required_role: ["owner"])])
    owner_only_owner_cookie = sign_up_cookie(owner_only, "owner-only@example.com")
    owner_only_admin_cookie = sign_up_cookie(owner_only, "owner-only-admin@example.com")
    owner_only_admin = owner_only.api.get_session(headers: {"cookie" => owner_only_admin_cookie}).fetch(:user)
    owner_only_org = owner_only.api.create_organization(headers: {"cookie" => owner_only_owner_cookie}, body: {name: "Owner Only", slug: "owner-only"})
    owner_only.api.add_member(headers: {"cookie" => owner_only_owner_cookie}, body: {organizationId: owner_only_org.fetch("id"), userId: owner_only_admin.fetch("id"), role: "admin"})
    forbidden = assert_raises(BetterAuth::APIError) do
      owner_only.api.generate_scim_token(headers: {"cookie" => owner_only_admin_cookie}, body: {providerId: "blocked", organizationId: owner_only_org.fetch("id")})
    end
    assert_equal 403, forbidden.status_code

    founder_auth = build_auth(plugins: [BetterAuth::Plugins.organization(creator_role: "founder"), BetterAuth::Plugins.scim])
    founder_cookie = sign_up_cookie(founder_auth, "founder@example.com")
    founder_org = founder_auth.api.create_organization(headers: {"cookie" => founder_cookie}, body: {name: "Founder", slug: "founder"})
    founder_token = founder_auth.api.generate_scim_token(headers: {"cookie" => founder_cookie}, body: {providerId: "founder-okta", organizationId: founder_org.fetch("id")})
    assert_kind_of String, founder_token.fetch(:scimToken)
  end

  def test_scim_blocks_cross_org_provider_regeneration_and_delete_invalidates_org_token
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    other_cookie = sign_up_cookie(auth, "other@example.com")
    owner_org = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Owner Org", slug: "owner-org"})
    other_org = auth.api.create_organization(headers: {"cookie" => other_cookie}, body: {name: "Other Org", slug: "other-org"})
    token = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "shared", organizationId: owner_org.fetch("id")}).fetch(:scimToken)

    blocked = assert_raises(BetterAuth::APIError) do
      auth.api.generate_scim_token(headers: {"cookie" => other_cookie}, body: {providerId: "shared"})
    end
    assert_equal 403, blocked.status_code

    other_token = auth.api.generate_scim_token(headers: {"cookie" => other_cookie}, body: {providerId: "other", organizationId: other_org.fetch("id")}).fetch(:scimToken)
    assert auth.api.create_scim_user(headers: bearer(token), body: {userName: "owner-org@example.com"})
    assert auth.api.create_scim_user(headers: bearer(other_token), body: {userName: "other-org@example.com"})

    assert_equal true, auth.api.delete_scim_provider_connection(headers: {"cookie" => owner_cookie}, body: {providerId: "shared"}).fetch(:success)
    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.create_scim_user(headers: bearer(token), body: {userName: "after-delete@example.com"})
    end
    assert_equal 401, invalid.status_code
  end

  def test_scim_scopes_user_access_by_provider_and_deletes_users
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token_a = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "provider-a"}).fetch(:scimToken)
    token_b = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "provider-b"}).fetch(:scimToken)
    user_a = auth.api.create_scim_user(headers: bearer(token_a), body: {userName: "a@example.com"})
    user_b = auth.api.create_scim_user(headers: bearer(token_b), body: {userName: "b@example.com"})

    listed_a = auth.api.list_scim_users(headers: bearer(token_a))
    assert_equal [user_a.fetch(:id)], listed_a.fetch(:Resources).map { |user| user.fetch(:id) }

    not_found = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_user(headers: bearer(token_a), params: {userId: user_b.fetch(:id)})
    end
    assert_equal 404, not_found.status_code

    auth.api.delete_scim_user(headers: bearer(token_b), params: {userId: user_b.fetch(:id)}, return_status: true)
    deleted = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_user(headers: bearer(token_b), params: {userId: user_b.fetch(:id)})
    end
    assert_equal 404, deleted.status_code
  end

  def test_scim_org_scoping_empty_lists_and_missing_or_anonymous_access
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.scim])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    org_a = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Org A", slug: "org-a"})
    org_b = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Org B", slug: "org-b"})
    token_a = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "provider-a", organizationId: org_a.fetch("id")}).fetch(:scimToken)
    token_b = auth.api.generate_scim_token(headers: {"cookie" => owner_cookie}, body: {providerId: "provider-b", organizationId: org_b.fetch("id")}).fetch(:scimToken)

    assert_equal 0, auth.api.list_scim_users(headers: bearer(token_a)).fetch(:totalResults)
    user_a = auth.api.create_scim_user(headers: bearer(token_a), body: {userName: "org-a@example.com"})
    assert_equal [], auth.api.list_scim_users(headers: bearer(token_b)).fetch(:Resources)
    assert_equal [user_a.fetch(:id)], auth.api.list_scim_users(headers: bearer(token_a)).fetch(:Resources).map { |user| user.fetch(:id) }

    assert_equal 401, auth.api.list_scim_users(as_response: true).first
    assert_equal 401, auth.api.get_scim_user(as_response: true, params: {userId: user_a.fetch(:id)}).first
    assert_equal 401, auth.api.delete_scim_user(as_response: true, params: {userId: user_a.fetch(:id)}).first

    missing_get = assert_raises(BetterAuth::APIError) do
      auth.api.get_scim_user(headers: bearer(token_a), params: {userId: "missing"})
    end
    assert_equal 404, missing_get.status_code

    missing_delete = assert_raises(BetterAuth::APIError) do
      auth.api.delete_scim_user(headers: bearer(token_a), params: {userId: "missing"})
    end
    assert_equal 404, missing_delete.status_code
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

  private

  def build_auth(options = nil, plugins: nil, **kwargs)
    options = (options || {}).merge(kwargs)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: plugins || [BetterAuth::Plugins.scim(options)]
    )
  end

  def sign_up_cookie(auth, email = "owner@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Owner"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def bearer(token)
    {"authorization" => "Bearer #{token}"}
  end
end
