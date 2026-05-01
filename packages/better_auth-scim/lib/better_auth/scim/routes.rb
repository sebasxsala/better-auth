# frozen_string_literal: true

require "base64"

module BetterAuth
  module Plugins
    module_function

    def scim_generate_token_endpoint(config)
      Endpoint.new(path: "/scim/generate-token", method: "POST", metadata: scim_openapi_metadata("Generates a new SCIM token for the given provider")) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        raw_provider_id = body[:provider_id]
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VALIDATION_ERROR"]) unless raw_provider_id.is_a?(String)

        provider_id = raw_provider_id
        organization_id = body[:organization_id]
        if body.key?(:organization_id) && !organization_id.nil? && !organization_id.is_a?(String)
          raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VALIDATION_ERROR"])
        end
        raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["MISSING_FIELD"]) if provider_id.empty?
        raise APIError.new("BAD_REQUEST", message: "Provider id contains forbidden characters") if provider_id.include?(":")
        required_roles = scim_required_roles(ctx, config)
        if organization_id && !scim_has_organization_plugin?(ctx)
          raise APIError.new("BAD_REQUEST", message: "Restricting a token to an organization requires the organization plugin")
        end

        member = nil
        if organization_id
          member = scim_find_organization_member(ctx, session.fetch(:user).fetch("id"), organization_id)
          raise APIError.new("FORBIDDEN", message: "You are not a member of the organization") unless member
          raise APIError.new("FORBIDDEN", message: "Insufficient role for this operation") unless scim_has_required_role?(member.fetch("role", ""), required_roles)
        end

        where = [{field: "providerId", value: provider_id}]
        where << {field: "organizationId", value: organization_id} if organization_id
        existing = ctx.context.adapter.find_one(model: "scimProvider", where: where)
        if existing
          scim_assert_provider_access!(ctx, session.fetch(:user).fetch("id"), existing, required_roles)
          ctx.context.adapter.delete(model: "scimProvider", where: [{field: "id", value: existing.fetch("id")}])
        end

        base_token = Crypto.random_string(24)
        token = Base64.urlsafe_encode64([base_token, provider_id, organization_id].compact.join(":"), padding: false)
        scim_call_token_hook(config[:before_scim_token_generated], user: session.fetch(:user), member: member, scim_token: token)
        stored = scim_store_token(ctx, config, base_token)
        data = {providerId: provider_id, scimToken: stored, organizationId: organization_id}
        data[:userId] = session.fetch(:user).fetch("id") if scim_provider_ownership_enabled?(config)
        provider = ctx.context.adapter.create(model: "scimProvider", data: data)
        scim_call_token_hook(config[:after_scim_token_generated], user: session.fetch(:user), member: member, scim_token: token, scim_provider: provider)
        ctx.json({scimToken: token}, status: 201)
      end
    end

    def scim_list_provider_connections_endpoint(config)
      Endpoint.new(path: "/scim/list-provider-connections", method: "GET", metadata: scim_openapi_metadata("List SCIM provider connections.")) do |ctx|
        session = Routes.current_session(ctx)
        user_id = session.fetch(:user).fetch("id")
        required_roles = scim_required_roles(ctx, config)
        org_memberships = scim_has_organization_plugin?(ctx) ? scim_user_org_memberships(ctx, user_id) : {}
        providers = ctx.context.adapter.find_many(model: "scimProvider").select do |provider|
          organization_id = provider["organizationId"]
          if organization_id
            member = org_memberships[organization_id]
            member && scim_has_required_role?(member.fetch("role", ""), required_roles)
          else
            !provider.key?("userId") || provider["userId"].nil? || provider["userId"] == user_id
          end
        end
        ctx.json({providers: providers.map { |provider| scim_normalized_provider(provider) }})
      end
    end

    def scim_get_provider_connection_endpoint(config)
      Endpoint.new(path: "/scim/get-provider-connection", method: "GET", metadata: scim_openapi_metadata("Get SCIM provider connection.")) do |ctx|
        session = Routes.current_session(ctx)
        provider = scim_provider_by_provider_id!(ctx, scim_provider_id_query(ctx))
        scim_assert_provider_access!(ctx, session.fetch(:user).fetch("id"), provider, scim_required_roles(ctx, config))
        ctx.json(scim_normalized_provider(provider))
      end
    end

    def scim_delete_provider_connection_endpoint(config)
      Endpoint.new(path: "/scim/delete-provider-connection", method: "POST", metadata: scim_openapi_metadata("Delete SCIM provider connection.")) do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        provider = scim_provider_by_provider_id!(ctx, body[:provider_id])
        scim_assert_provider_access!(ctx, session.fetch(:user).fetch("id"), provider, scim_required_roles(ctx, config))
        ctx.context.adapter.delete(model: "scimProvider", where: [{field: "providerId", value: provider.fetch("providerId")}])
        ctx.json({success: true})
      end
    end

    def scim_create_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users", method: "POST", metadata: scim_hidden_metadata("Create SCIM user.", SCIM_SUPPORTED_MEDIA_TYPES), use: [scim_auth_middleware(config)]) do |ctx|
        body = normalize_hash(ctx.body)
        scim_validate_user_body!(body)
        provider = ctx.context.scim_provider
        provider_id = provider.fetch("providerId")
        email = scim_primary_email(body).downcase
        account_id = scim_account_id(body)
        existing_account = ctx.context.adapter.find_one(model: "account", where: [{field: "accountId", value: account_id}, {field: "providerId", value: provider_id}])
        raise scim_error("CONFLICT", "User already exists", scim_type: "uniqueness") if existing_account

        user, account = ctx.context.adapter.transaction do
          user = ctx.context.internal_adapter.find_user_by_email(email)&.fetch(:user)
          user ||= ctx.context.internal_adapter.create_user(
            email: email,
            name: scim_display_name(body, email),
            emailVerified: true
          )
          account = ctx.context.internal_adapter.create_account(
            userId: user.fetch("id"),
            providerId: provider_id,
            accountId: account_id,
            accessToken: "",
            refreshToken: ""
          )
          scim_create_org_membership(ctx, user.fetch("id"), provider["organizationId"])
          [user, account]
        end
        resource = scim_user_resource(user, account, ctx.context.base_url)
        ctx.json(resource, status: 201, headers: {location: resource.fetch(:meta).fetch(:location)})
      end
    end

    def scim_update_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users/:userId", method: "PUT", metadata: scim_hidden_metadata("Update SCIM user.", SCIM_SUPPORTED_MEDIA_TYPES), use: [scim_auth_middleware(config)]) do |ctx|
        user, account = scim_find_user_with_account!(ctx)
        body = normalize_hash(ctx.body)
        scim_validate_user_body!(body)
        updated, updated_account = ctx.context.adapter.transaction do
          [
            ctx.context.internal_adapter.update_user(user.fetch("id"), scim_user_update(body)),
            ctx.context.internal_adapter.update_account(account.fetch("id"), accountId: scim_account_id(body), updatedAt: Time.now)
          ]
        end
        ctx.json(scim_user_resource(updated, updated_account, ctx.context.base_url))
      end
    end

    def scim_patch_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users/:userId", method: "PATCH", metadata: scim_hidden_metadata("Patch SCIM user.", SCIM_SUPPORTED_MEDIA_TYPES), use: [scim_auth_middleware(config)]) do |ctx|
        user, account = scim_find_user_with_account!(ctx)
        body = normalize_hash(ctx.body)
        scim_validate_patch_body!(body)
        update = {}
        account_update = {}
        Array(body[:operations] || ctx.body["Operations"]).each do |operation|
          op = normalize_hash(operation)
          operation_name = op[:op].to_s.empty? ? "replace" : op[:op].to_s.downcase
          raise scim_error("BAD_REQUEST", "Invalid SCIM patch operation") unless %w[replace add remove].include?(operation_name)

          if op[:value].is_a?(Hash)
            patch_path = op[:path].to_s.empty? ? nil : op[:path]
            scim_apply_patch_value!(user, update, account_update, normalize_hash(op[:value]), operation_name, patch_path)
            next
          end

          scim_apply_patch_path!(user, update, account_update, op[:path], op[:value], operation_name)
        end
        raise scim_error("BAD_REQUEST", "No valid fields to update") if update.empty? && account_update.empty?

        ctx.context.internal_adapter.update_user(user.fetch("id"), update.merge(updatedAt: Time.now)) unless update.empty?
        ctx.context.internal_adapter.update_account(account.fetch("id"), account_update.merge(updatedAt: Time.now)) unless account_update.empty?
        ctx.json(nil, status: 204)
      end
    end

    def scim_delete_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users/:userId", method: "DELETE", metadata: scim_hidden_metadata("Delete SCIM user.", [*SCIM_SUPPORTED_MEDIA_TYPES, ""]), use: [scim_auth_middleware(config)]) do |ctx|
        user, = scim_find_user_with_account!(ctx)
        ctx.context.internal_adapter.delete_user(user.fetch("id"))
        ctx.json(nil, status: 204)
      end
    end

    def scim_list_users_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users", method: "GET", metadata: scim_hidden_metadata("List SCIM users.", SCIM_SUPPORTED_MEDIA_TYPES), use: [scim_auth_middleware(config)]) do |ctx|
        provider = ctx.context.scim_provider
        accounts = ctx.context.adapter.find_many(model: "account", where: [{field: "providerId", value: provider.fetch("providerId")}])
        users_by_id = ctx.context.internal_adapter.list_users.each_with_object({}) { |user, result| result[user.fetch("id")] = user }
        users = accounts.filter_map { |account| users_by_id[account.fetch("userId")] }
        if provider["organizationId"]
          member_ids = ctx.context.adapter.find_many(
            model: "member",
            where: [{field: "organizationId", value: provider.fetch("organizationId")}]
          ).map { |member| member.fetch("userId") }
          users = users.select { |user| member_ids.include?(user.fetch("id")) }
        end
        filter_field, filter_value = scim_parse_filter(ctx.query[:filter] || ctx.query["filter"]) if ctx.query[:filter] || ctx.query["filter"]
        resources = users.filter_map do |user|
          account = accounts.find { |entry| entry.fetch("userId") == user.fetch("id") }
          resource = scim_user_resource(user, account, ctx.context.base_url)
          next resource unless filter_field

          (resource[filter_field.to_sym].to_s.downcase == filter_value.to_s.downcase) ? resource : nil
        end
        ctx.json({schemas: [SCIM_LIST_RESPONSE_SCHEMA], totalResults: resources.length, itemsPerPage: resources.length, startIndex: 1, Resources: resources})
      end
    end

    def scim_get_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users/:userId", method: "GET", metadata: scim_hidden_metadata("Get SCIM user.", SCIM_SUPPORTED_MEDIA_TYPES), use: [scim_auth_middleware(config)]) do |ctx|
        user, account = scim_find_user_with_account!(ctx)
        ctx.json(scim_user_resource(user, account, ctx.context.base_url))
      end
    end

    def scim_service_provider_config_endpoint
      Endpoint.new(path: "/scim/v2/ServiceProviderConfig", method: "GET", metadata: scim_hidden_metadata("SCIM Service Provider Configuration", SCIM_SUPPORTED_MEDIA_TYPES)) do |ctx|
        ctx.json({
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
          patch: {supported: true},
          bulk: {supported: false},
          filter: {supported: true},
          changePassword: {supported: false},
          sort: {supported: false},
          etag: {supported: false},
          authenticationSchemes: [{
            type: "oauthbearertoken",
            name: "OAuth Bearer Token",
            description: "Authentication scheme using the Authorization header with a bearer token tied to an organization.",
            specUri: "http://www.rfc-editor.org/info/rfc6750",
            primary: true
          }],
          meta: {resourceType: "ServiceProviderConfig"}
        })
      end
    end

    def scim_schemas_endpoint
      Endpoint.new(path: "/scim/v2/Schemas", method: "GET", metadata: scim_hidden_metadata("List SCIM schemas.", SCIM_SUPPORTED_MEDIA_TYPES)) do |ctx|
        resource = scim_user_schema(ctx.context.base_url)
        ctx.json({schemas: [SCIM_LIST_RESPONSE_SCHEMA], Resources: [resource], totalResults: 1, itemsPerPage: 1, startIndex: 1})
      end
    end

    def scim_schema_endpoint
      Endpoint.new(path: "/scim/v2/Schemas/:schemaId", method: "GET", metadata: scim_hidden_metadata("Get SCIM schema.", SCIM_SUPPORTED_MEDIA_TYPES)) do |ctx|
        raise scim_error("NOT_FOUND", "Schema not found") unless scim_param(ctx, :schema_id).to_s == SCIM_USER_SCHEMA_ID

        ctx.json(scim_user_schema(ctx.context.base_url))
      end
    end

    def scim_resource_types_endpoint
      Endpoint.new(path: "/scim/v2/ResourceTypes", method: "GET", metadata: scim_hidden_metadata("List SCIM resource types.", SCIM_SUPPORTED_MEDIA_TYPES)) do |ctx|
        resource = scim_user_resource_type(ctx.context.base_url)
        ctx.json({schemas: [SCIM_LIST_RESPONSE_SCHEMA], Resources: [resource], totalResults: 1, itemsPerPage: 1, startIndex: 1})
      end
    end

    def scim_resource_type_endpoint
      Endpoint.new(path: "/scim/v2/ResourceTypes/:resourceTypeId", method: "GET", metadata: scim_hidden_metadata("Get SCIM resource type.", SCIM_SUPPORTED_MEDIA_TYPES)) do |ctx|
        raise scim_error("NOT_FOUND", "Resource type not found") unless scim_param(ctx, :resource_type_id) == "User"

        ctx.json(scim_user_resource_type(ctx.context.base_url))
      end
    end

    def scim_find_user_with_account!(ctx)
      provider = ctx.context.scim_provider
      user_id = scim_param(ctx, :user_id)
      account = ctx.context.adapter.find_one(
        model: "account",
        where: [
          {field: "userId", value: user_id},
          {field: "providerId", value: provider.fetch("providerId")}
        ]
      )
      user = account && ctx.context.internal_adapter.find_user_by_id(user_id)
      if user && provider["organizationId"]
        member = ctx.context.adapter.find_one(
          model: "member",
          where: [{field: "organizationId", value: provider.fetch("organizationId")}, {field: "userId", value: user_id}]
        )
        user = nil unless member
      end
      raise scim_error("NOT_FOUND", "User not found") unless user && account

      [user, account]
    end

    def scim_validate_user_body!(body)
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) unless body[:user_name].is_a?(String)
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if body[:user_name].empty?
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if body.key?(:external_id) && !body[:external_id].is_a?(String)
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if body.key?(:name) && !body[:name].is_a?(Hash)
      raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if body.key?(:emails) && !body[:emails].is_a?(Array)
      normalize_hash(body[:name] || {}).each_value do |value|
        raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) unless value.is_a?(String)
      end

      Array(body[:emails]).each do |email|
        email = normalize_hash(email)
        value = email[:value]
        raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) if email.key?(:primary) && ![true, false].include?(email[:primary])
        raise scim_error("BAD_REQUEST", BASE_ERROR_CODES["VALIDATION_ERROR"]) unless value.to_s.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
      end
    end

    def scim_validate_patch_body!(body)
      schemas = Array(body[:schemas])
      return if schemas.include?("urn:ietf:params:scim:api:messages:2.0:PatchOp")

      raise scim_error("BAD_REQUEST", "Invalid schemas for PatchOp")
    end

    def scim_has_organization_plugin?(ctx)
      Array(ctx.context.options.plugins).any? { |plugin| plugin.id == "organization" }
    end

    def scim_organization_plugin(ctx)
      Array(ctx.context.options.plugins).find { |plugin| plugin.id == "organization" }
    end

    def scim_required_roles(ctx, config)
      configured = config[:required_role] || config[:required_roles]
      return Array(configured).map(&:to_s) if configured

      creator_role = scim_organization_plugin(ctx)&.options&.fetch(:creator_role, nil)
      ["admin", creator_role || "owner"].uniq
    end

    def scim_provider_ownership_enabled?(config)
      normalize_hash(config[:provider_ownership] || {})[:enabled] == true
    end

    def scim_find_organization_member(ctx, user_id, organization_id)
      ctx.context.adapter.find_one(
        model: "member",
        where: [
          {field: "userId", value: user_id},
          {field: "organizationId", value: organization_id}
        ]
      )
    end

    def scim_parse_roles(role)
      Array(role).flat_map { |entry| entry.to_s.split(",") }.map(&:strip).reject(&:empty?)
    end

    def scim_has_required_role?(role, required_roles)
      required = Array(required_roles).map(&:to_s)
      required.empty? || scim_parse_roles(role).any? { |candidate| required.include?(candidate) }
    end

    def scim_user_org_memberships(ctx, user_id)
      ctx.context.adapter.find_many(model: "member", where: [{field: "userId", value: user_id}]).each_with_object({}) do |member, result|
        result[member.fetch("organizationId")] = member
      end
    end

    def scim_assert_provider_access!(ctx, user_id, provider, required_roles)
      return unless provider

      organization_id = provider["organizationId"]
      if organization_id
        raise APIError.new("FORBIDDEN", message: "Organization plugin is required to access this SCIM provider") unless scim_has_organization_plugin?(ctx)

        member = scim_find_organization_member(ctx, user_id, organization_id)
        raise APIError.new("FORBIDDEN", message: "You must be a member of the organization to access this provider") unless member
        raise APIError.new("FORBIDDEN", message: "Insufficient role for this operation") unless scim_has_required_role?(member.fetch("role", ""), required_roles)
      elsif provider.key?("userId") && provider["userId"] && provider["userId"] != user_id
        raise APIError.new("FORBIDDEN", message: "You must be the owner to access this provider")
      end
    end

    def scim_provider_by_provider_id!(ctx, provider_id)
      raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES["VALIDATION_ERROR"]) unless provider_id.is_a?(String)

      provider = ctx.context.adapter.find_one(model: "scimProvider", where: [{field: "providerId", value: provider_id.to_s}])
      raise APIError.new("NOT_FOUND", message: "SCIM provider not found") unless provider

      provider
    end

    def scim_provider_id_query(ctx)
      ctx.query[:providerId] || ctx.query[:provider_id] || ctx.query["providerId"] || ctx.query["provider_id"]
    end

    def scim_normalized_provider(provider)
      {
        id: provider.fetch("id"),
        providerId: provider.fetch("providerId"),
        organizationId: provider["organizationId"]
      }
    end

    def scim_call_token_hook(callback, payload)
      callback.call(payload) if callback.respond_to?(:call)
    end

    def scim_create_org_membership(ctx, user_id, organization_id)
      return unless organization_id
      return if ctx.context.adapter.find_one(model: "member", where: [{field: "organizationId", value: organization_id}, {field: "userId", value: user_id}])

      ctx.context.adapter.create(model: "member", data: {userId: user_id, organizationId: organization_id, role: "member", createdAt: Time.now})
    end
  end
end
