# frozen_string_literal: true

require "securerandom"

module BetterAuth
  module Plugins
    module_function

    def scim(options = {})
      config = {store_scim_token: "plain"}.merge(normalize_hash(options))
      Plugin.new(
        id: "scim",
        schema: scim_schema,
        endpoints: {
          generate_scim_token: scim_generate_token_endpoint(config),
          create_scim_user: scim_create_user_endpoint(config),
          update_scim_user: scim_update_user_endpoint(config),
          patch_scim_user: scim_patch_user_endpoint(config),
          delete_scim_user: scim_delete_user_endpoint(config),
          list_scim_users: scim_list_users_endpoint(config),
          get_scim_user: scim_get_user_endpoint(config),
          get_scim_service_provider_config: scim_service_provider_config_endpoint,
          get_scim_schemas: scim_schemas_endpoint,
          get_scim_schema: scim_schema_endpoint,
          get_scim_resource_types: scim_resource_types_endpoint,
          get_scim_resource_type: scim_resource_type_endpoint
        },
        options: config
      )
    end

    def scim_schema
      {
        scimProvider: {
          fields: {
            providerId: {type: "string", required: true, unique: true},
            scimToken: {type: "string", required: true, unique: true},
            organizationId: {type: "string", required: false}
          }
        },
        user: {
          fields: {
            active: {type: "boolean", required: false, default_value: true},
            externalId: {type: "string", required: false}
          }
        }
      }
    end

    def scim_generate_token_endpoint(config)
      Endpoint.new(path: "/scim/generate-token", method: "POST") do |ctx|
        Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        provider_id = body[:provider_id].to_s
        raise APIError.new("BAD_REQUEST", message: "Provider id contains forbidden characters") if provider_id.match?(/[:\/\s]/)

        token = "scim_#{SecureRandom.hex(24)}"
        stored = scim_store_token(config, token)
        existing = ctx.context.adapter.find_one(model: "scimProvider", where: [{field: "providerId", value: provider_id}])
        data = {providerId: provider_id, scimToken: stored, organizationId: body[:organization_id]}
        if existing
          ctx.context.adapter.update(model: "scimProvider", where: [{field: "id", value: existing.fetch("id")}], update: data)
        else
          ctx.context.adapter.create(model: "scimProvider", data: data)
        end
        ctx.json({scimToken: token}, status: 201)
      end
    end

    def scim_create_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users", method: "POST", use: [scim_auth_middleware(config)]) do |ctx|
        body = normalize_hash(ctx.body)
        email = body[:user_name].to_s.downcase
        name = scim_display_name(body)
        user = ctx.context.internal_adapter.create_user(
          email: email,
          name: name.empty? ? email : name,
          emailVerified: true,
          active: body.key?(:active) ? body[:active] : true,
          externalId: body[:external_id]
        )
        ctx.json(scim_user_resource(user), status: 201)
      end
    end

    def scim_update_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users/:userId", method: "PUT", use: [scim_auth_middleware(config)]) do |ctx|
        user = scim_find_user!(ctx)
        body = normalize_hash(ctx.body)
        updated = ctx.context.internal_adapter.update_user(user.fetch("id"), scim_user_update(body))
        ctx.json(scim_user_resource(updated))
      end
    end

    def scim_patch_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users/:userId", method: "PATCH", use: [scim_auth_middleware(config)]) do |ctx|
        user = scim_find_user!(ctx)
        update = {}
        Array(normalize_hash(ctx.body)[:operations] || ctx.body["Operations"]).each do |operation|
          op = normalize_hash(operation)
          operation_name = op[:op].to_s.downcase
          raise APIError.new("BAD_REQUEST", message: "Invalid SCIM patch operation") unless %w[replace add remove].include?(operation_name)

          if op[:path].to_s.empty? && op[:value].is_a?(Hash)
            scim_apply_patch_value!(update, normalize_hash(op[:value]), remove: false)
            next
          end

          scim_apply_patch_path!(update, op[:path], op[:value], remove: operation_name == "remove")
        end
        ctx.context.internal_adapter.update_user(user.fetch("id"), update) unless update.empty?
        ctx.json(nil, status: 204)
      end
    end

    def scim_delete_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users/:userId", method: "DELETE", metadata: {allowed_media_types: ["application/json", ""]}, use: [scim_auth_middleware(config)]) do |ctx|
        user = scim_find_user!(ctx)
        ctx.context.internal_adapter.update_user(user.fetch("id"), active: false)
        ctx.json(nil, status: 204)
      end
    end

    def scim_list_users_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users", method: "GET", use: [scim_auth_middleware(config)]) do |ctx|
        users = ctx.context.internal_adapter.list_users
        if (filter = ctx.query[:filter] || ctx.query["filter"])
          field, value = scim_parse_filter(filter)
          users = users.select { |user| scim_filter_value(user, field) == value }
        end
        resources = users.map { |user| scim_user_resource(user) }
        ctx.json({schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults: resources.length, itemsPerPage: resources.length, startIndex: 1, Resources: resources})
      end
    end

    def scim_get_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users/:userId", method: "GET", use: [scim_auth_middleware(config)]) do |ctx|
        ctx.json(scim_user_resource(scim_find_user!(ctx)))
      end
    end

    def scim_service_provider_config_endpoint
      Endpoint.new(path: "/scim/v2/ServiceProviderConfig", method: "GET") do |ctx|
        ctx.json({
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
          patch: {supported: true},
          filter: {supported: true, maxResults: 100},
          changePassword: {supported: false},
          sort: {supported: false},
          etag: {supported: false},
          authenticationSchemes: [{type: "oauthbearertoken", name: "OAuth Bearer Token"}]
        })
      end
    end

    def scim_schemas_endpoint
      Endpoint.new(path: "/scim/v2/Schemas", method: "GET") do |ctx|
        ctx.json({Resources: [scim_user_schema], totalResults: 1})
      end
    end

    def scim_schema_endpoint
      Endpoint.new(path: "/scim/v2/Schemas/:schemaId", method: "GET") do |ctx|
        raise APIError.new("NOT_FOUND", message: "Schema not found") unless scim_param(ctx, :schema_id).to_s.end_with?("User")

        ctx.json(scim_user_schema)
      end
    end

    def scim_resource_types_endpoint
      Endpoint.new(path: "/scim/v2/ResourceTypes", method: "GET") do |ctx|
        ctx.json({Resources: [scim_user_resource_type], totalResults: 1})
      end
    end

    def scim_resource_type_endpoint
      Endpoint.new(path: "/scim/v2/ResourceTypes/:resourceTypeId", method: "GET") do |ctx|
        raise APIError.new("NOT_FOUND", message: "Resource type not found") unless scim_param(ctx, :resource_type_id) == "User"

        ctx.json(scim_user_resource_type)
      end
    end

    def scim_auth_middleware(config)
      lambda do |ctx|
        token = ctx.headers["authorization"].to_s.sub(/\ABearer\s+/i, "")
        provider = ctx.context.adapter.find_many(model: "scimProvider").find { |entry| scim_token_matches?(config, token, entry.fetch("scimToken")) }
        raise APIError.new("UNAUTHORIZED", message: "Invalid SCIM token") unless provider

        ctx.context.apply_plugin_context!(scim_provider: provider)
        nil
      end
    end

    def scim_store_token(config, token)
      storage = config[:store_scim_token]
      if storage == "hashed"
        Crypto.sha256(token)
      elsif storage.is_a?(Hash) && storage[:hash].respond_to?(:call)
        storage[:hash].call(token)
      else
        token
      end
    end

    def scim_token_matches?(config, token, stored)
      !token.to_s.empty? && scim_store_token(config, token) == stored
    end

    def scim_find_user!(ctx)
      user = ctx.context.internal_adapter.find_user_by_id(scim_param(ctx, :user_id))
      raise APIError.new("NOT_FOUND", message: "User not found") unless user

      user
    end

    def scim_user_update(body)
      {
        email: body[:user_name]&.downcase,
        name: scim_display_name(body),
        active: body.key?(:active) ? body[:active] : nil,
        externalId: body[:external_id]
      }.compact
    end

    def scim_apply_patch_value!(update, value, remove:)
      scim_apply_patch_path!(update, "userName", value[:user_name], remove: remove) if value.key?(:user_name)
      scim_apply_patch_path!(update, "externalId", value[:external_id], remove: remove) if value.key?(:external_id)
      scim_apply_patch_path!(update, "active", value[:active], remove: remove) if value.key?(:active)
    end

    def scim_apply_patch_path!(update, path, value, remove:)
      normalized = path.to_s.sub(%r{\A/+}, "")
      case normalized
      when "active"
        update[:active] = remove ? nil : value
      when "userName"
        update[:email] = remove ? nil : value.to_s.downcase
      when "externalId"
        update[:externalId] = remove ? nil : value
      else
        raise APIError.new("BAD_REQUEST", message: "Invalid SCIM patch path")
      end
    end

    def scim_display_name(body)
      name = normalize_hash(body[:name] || {})
      [name[:given_name], name[:family_name]].compact.join(" ").strip
    end

    def scim_user_resource(user)
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        id: user.fetch("id"),
        userName: user.fetch("email"),
        externalId: user["externalId"],
        displayName: user["name"],
        active: user.key?("active") ? user["active"] : true,
        name: {formatted: user["name"]},
        meta: {resourceType: "User"}
      }.compact
    end

    def scim_filter_value(user, field)
      case field
      when "userName" then user["email"]
      when "externalId" then user["externalId"]
      else user[field]
      end
    end

    def scim_parse_filter(filter)
      match = filter.to_s.match(/\A(\w+)\s+eq\s+"([^"]+)"\z/)
      raise APIError.new("BAD_REQUEST", message: "Invalid SCIM filter") unless match

      field = match[1]
      raise APIError.new("BAD_REQUEST", message: "Invalid SCIM filter") unless %w[userName externalId].include?(field)

      [field, match[2]]
    end

    def scim_user_schema
      {id: "urn:ietf:params:scim:schemas:core:2.0:User", name: "User", attributes: [{name: "userName", type: "string"}, {name: "active", type: "boolean"}]}
    end

    def scim_user_resource_type
      {id: "User", name: "User", endpoint: "/Users", schema: "urn:ietf:params:scim:schemas:core:2.0:User"}
    end

    def scim_param(ctx, key)
      ctx.params[key] || ctx.params[key.to_s] || ctx.params[Schema.storage_key(key)] || ctx.params[Schema.storage_key(key).to_sym]
    end
  end
end
