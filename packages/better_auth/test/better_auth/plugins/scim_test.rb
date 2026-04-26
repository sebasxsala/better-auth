# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsSCIMTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_generates_plain_hashed_and_custom_scim_tokens
    plain = build_auth(store_scim_token: "plain")
    plain_cookie = sign_up_cookie(plain)
    plain_token = plain.api.generate_scim_token(headers: {"cookie" => plain_cookie}, body: {providerId: "plain-provider"})
    assert_match(/\Ascim_/, plain_token.fetch(:scimToken))
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

  private

  def build_auth(options = {})
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.scim(options)]
    )
  end

  def sign_up_cookie(auth)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "owner@example.com", password: "password123", name: "Owner"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def bearer(token)
    {"authorization" => "Bearer #{token}"}
  end
end
