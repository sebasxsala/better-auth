# frozen_string_literal: true

require "json"
require_relative "../test_helper"

class BetterAuthPluginsSCIMTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

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

    schemas = auth.api.get_scim_schemas
    assert_operator schemas.fetch(:Resources).length, :>=, 1

    user_schema = auth.api.get_scim_schema(params: {schemaId: "urn:ietf:params:scim:schemas:core:2.0:User"})
    assert_equal "User", user_schema.fetch(:name)

    resource_types = auth.api.get_scim_resource_types
    assert_equal ["User"], resource_types.fetch(:Resources).map { |resource| resource.fetch(:name) }

    resource_type = auth.api.get_scim_resource_type(params: {resourceTypeId: "User"})
    assert_equal "/Users", resource_type.fetch(:endpoint)
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
        name: {givenName: "SCIM", familyName: "User"},
        active: true
      }
    )
    assert_equal "scim@example.com", created.fetch(:userName)
    assert_equal "external-1", created.fetch(:externalId)

    listed = auth.api.list_scim_users(headers: headers, query: {filter: 'userName eq "scim@example.com"'})
    assert_equal 1, listed.fetch(:totalResults)

    fetched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "SCIM User", fetched.fetch(:displayName)

    updated = auth.api.update_scim_user(headers: headers, params: {userId: created.fetch(:id)}, body: {userName: "updated@example.com", active: true})
    assert_equal "updated@example.com", updated.fetch(:userName)

    patch_status = auth.api.patch_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {Operations: [{op: "replace", path: "active", value: false}]},
      return_status: true
    )
    assert_equal 204, patch_status.fetch(:status)

    deleted = auth.api.delete_scim_user(headers: headers, params: {userId: created.fetch(:id)}, return_status: true)
    assert_equal 204, deleted.fetch(:status)
  end

  def test_scim_patch_supports_slash_paths_remove_and_no_path_value_object
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
          {op: "remove", path: "/externalId"}
        ]
      },
      return_status: true
    )
    patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "patched@example.com", patched.fetch(:userName)
    refute patched.key?(:externalId)

    auth.api.patch_scim_user(
      headers: headers,
      params: {userId: created.fetch(:id)},
      body: {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [
          {op: "add", value: {userName: "object@example.com", externalId: "external-2", active: false}}
        ]
      },
      return_status: true
    )
    object_patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
    assert_equal "object@example.com", object_patched.fetch(:userName)
    assert_equal "external-2", object_patched.fetch(:externalId)
    assert_equal false, object_patched.fetch(:active)
  end

  def test_scim_filters_external_id_and_rejects_invalid_filter_syntax
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)
    auth.api.create_scim_user(headers: headers, body: {userName: "a@example.com", externalId: "external-a"})
    auth.api.create_scim_user(headers: headers, body: {userName: "b@example.com", externalId: "external-b"})

    listed = auth.api.list_scim_users(headers: headers, query: {filter: 'externalId eq "external-b"'})
    assert_equal 1, listed.fetch(:totalResults)
    assert_equal "external-b", listed.fetch(:Resources).first.fetch(:externalId)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.list_scim_users(headers: headers, query: {filter: 'userName co "example.com"'})
    end
    assert_equal 400, error.status_code
    assert_equal 'The operator "co" is not supported', error.message
  end

  def test_scim_filters_external_id_from_linked_account_and_rejects_unsupported_operators
    auth = build_auth
    cookie = sign_up_cookie(auth)
    token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
    headers = bearer(token)

    auth.context.internal_adapter.create_user(email: "existing@example.com", name: "Existing User", emailVerified: true)
    created = auth.api.create_scim_user(
      headers: headers,
      body: {userName: "existing@example.com", externalId: "external-existing"}
    )
    assert_equal "external-existing", created.fetch(:externalId)

    listed = auth.api.list_scim_users(headers: headers, query: {filter: 'externalId eq "external-existing"'})
    assert_equal 1, listed.fetch(:totalResults)
    assert_equal created.fetch(:id), listed.fetch(:Resources).first.fetch(:id)

    %w[ne co sw ew pr].each do |operator|
      error = assert_raises(BetterAuth::APIError) do
        auth.api.list_scim_users(headers: headers, query: {filter: %(userName #{operator} "existing@example.com")})
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
