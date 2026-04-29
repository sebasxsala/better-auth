# frozen_string_literal: true

require "base64"
require "securerandom"

module BetterAuth
  module Plugins
    module_function

    remove_method :scim if method_defined?(:scim) || private_method_defined?(:scim)
    singleton_class.remove_method(:scim) if singleton_class.method_defined?(:scim) || singleton_class.private_method_defined?(:scim)

    def scim(options = {})
      config = {store_scim_token: "plain"}.merge(normalize_hash(options))
      Plugin.new(
        id: "scim",
        schema: scim_schema,
        endpoints: {
          generate_scim_token: scim_generate_token_endpoint(config),
          list_scim_provider_connections: scim_list_provider_connections_endpoint(config),
          get_scim_provider_connection: scim_get_provider_connection_endpoint(config),
          delete_scim_provider_connection: scim_delete_provider_connection_endpoint(config),
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
            organizationId: {type: "string", required: false},
            userId: {type: "string", required: false}
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
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        provider_id = body[:provider_id].to_s
        organization_id = body[:organization_id]
        raise APIError.new("BAD_REQUEST", message: "Provider id contains forbidden characters") if provider_id.include?(":")
        if organization_id && !scim_has_organization_plugin?(ctx)
          raise APIError.new("BAD_REQUEST", message: "Restricting a token to an organization requires the organization plugin")
        end

        required_roles = scim_required_roles(ctx, config)
        if organization_id
          member = scim_find_organization_member(ctx, session.fetch(:user).fetch("id"), organization_id)
          raise APIError.new("FORBIDDEN", message: "You are not a member of the organization") unless member
          raise APIError.new("FORBIDDEN", message: "Insufficient role for this operation") unless scim_has_required_role?(member.fetch("role"), required_roles)
        end

        base_token = Crypto.random_string(24)
        token = Base64.urlsafe_encode64([base_token, provider_id, organization_id].compact.join(":"), padding: false)
        stored = scim_store_token(ctx, config, base_token)
        where = [{field: "providerId", value: provider_id}]
        where << {field: "organizationId", value: organization_id} if organization_id
        existing = ctx.context.adapter.find_one(model: "scimProvider", where: where)
        scim_assert_provider_access!(ctx, session.fetch(:user).fetch("id"), existing, required_roles) if existing
        data = {providerId: provider_id, scimToken: stored, organizationId: organization_id}
        data[:userId] = session.fetch(:user).fetch("id") if scim_provider_ownership_enabled?(config)
        ctx.context.adapter.delete(model: "scimProvider", where: [{field: "id", value: existing.fetch("id")}]) if existing
        ctx.context.adapter.create(model: "scimProvider", data: data)
        ctx.json({scimToken: token}, status: 201)
      end
    end

    def scim_list_provider_connections_endpoint(config)
      Endpoint.new(path: "/scim/list-provider-connections", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        user_id = session.fetch(:user).fetch("id")
        required_roles = scim_required_roles(ctx, config)
        memberships = scim_organization_memberships(ctx, user_id)
        providers = ctx.context.adapter.find_many(model: "scimProvider").select do |provider|
          organization_id = provider["organizationId"]
          if organization_id
            roles = memberships[organization_id] || []
            roles.any? { |role| required_roles.empty? || required_roles.include?(role) }
          else
            provider["userId"].to_s.empty? || provider["userId"] == user_id
          end
        end
        ctx.json({providers: providers.map { |provider| scim_provider_connection(provider) }})
      end
    end

    def scim_get_provider_connection_endpoint(config)
      Endpoint.new(path: "/scim/get-provider-connection", method: "GET") do |ctx|
        session = Routes.current_session(ctx)
        query = normalize_hash(ctx.query)
        provider = scim_find_provider_connection!(ctx, query[:provider_id])
        scim_assert_provider_access!(ctx, session.fetch(:user).fetch("id"), provider, scim_required_roles(ctx, config))
        ctx.json(scim_provider_connection(provider))
      end
    end

    def scim_delete_provider_connection_endpoint(config)
      Endpoint.new(path: "/scim/delete-provider-connection", method: "POST") do |ctx|
        session = Routes.current_session(ctx)
        body = normalize_hash(ctx.body)
        provider = scim_find_provider_connection!(ctx, body[:provider_id])
        scim_assert_provider_access!(ctx, session.fetch(:user).fetch("id"), provider, scim_required_roles(ctx, config))
        ctx.context.adapter.delete(model: "scimProvider", where: [{field: "providerId", value: provider.fetch("providerId")}])
        ctx.json({success: true})
      end
    end

    def scim_create_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users", method: "POST", use: [scim_auth_middleware(config)]) do |ctx|
        body = normalize_hash(ctx.body)
        provider = ctx.context.scim_provider
        provider_id = provider.fetch("providerId")
        email = scim_primary_email(body).downcase
        account_id = scim_account_id(body)
        existing_account = ctx.context.adapter.find_one(model: "account", where: [{field: "accountId", value: account_id}, {field: "providerId", value: provider_id}])
        raise APIError.new("CONFLICT", message: "User already exists") if existing_account

        user = ctx.context.internal_adapter.find_user_by_email(email)&.fetch(:user)
        user ||= ctx.context.internal_adapter.create_user(
          email: email,
          name: scim_display_name(body, email),
          emailVerified: true,
          active: body.key?(:active) ? body[:active] : true,
          externalId: body[:external_id]
        )
        account = ctx.context.internal_adapter.create_account(
          userId: user.fetch("id"),
          providerId: provider_id,
          accountId: account_id,
          accessToken: "",
          refreshToken: ""
        )
        scim_create_org_membership(ctx, user.fetch("id"), provider["organizationId"])
        ctx.json(scim_user_resource(user, account, ctx.context.base_url), status: 201)
      end
    end

    def scim_update_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users/:userId", method: "PUT", use: [scim_auth_middleware(config)]) do |ctx|
        user, account = scim_find_user_with_account!(ctx)
        body = normalize_hash(ctx.body)
        updated = ctx.context.internal_adapter.update_user(user.fetch("id"), scim_user_update(body))
        updated_account = ctx.context.internal_adapter.update_account(account.fetch("id"), accountId: scim_account_id(body))
        ctx.json(scim_user_resource(updated, updated_account, ctx.context.base_url))
      end
    end

    def scim_patch_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users/:userId", method: "PATCH", use: [scim_auth_middleware(config)]) do |ctx|
        user, account = scim_find_user_with_account!(ctx)
        update = {}
        account_update = {}
        Array(normalize_hash(ctx.body)[:operations] || ctx.body["Operations"]).each do |operation|
          op = normalize_hash(operation)
          operation_name = op[:op].to_s.downcase
          raise APIError.new("BAD_REQUEST", message: "Invalid SCIM patch operation") unless %w[replace add remove].include?(operation_name)

          if op[:path].to_s.empty? && op[:value].is_a?(Hash)
            scim_apply_patch_value!(user, update, account_update, normalize_hash(op[:value]), operation_name)
            next
          end

          scim_apply_patch_path!(user, update, account_update, op[:path], op[:value], operation_name)
        end
        raise APIError.new("BAD_REQUEST", message: "No valid fields to update") if update.empty? && account_update.empty?

        ctx.context.internal_adapter.update_user(user.fetch("id"), update) unless update.empty?
        ctx.context.internal_adapter.update_account(account.fetch("id"), account_update) unless account_update.empty?
        ctx.json(nil, status: 204)
      end
    end

    def scim_delete_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users/:userId", method: "DELETE", metadata: {allowed_media_types: ["application/json", ""]}, use: [scim_auth_middleware(config)]) do |ctx|
        user, = scim_find_user_with_account!(ctx)
        ctx.context.internal_adapter.delete_user(user.fetch("id"))
        ctx.json(nil, status: 204)
      end
    end

    def scim_list_users_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users", method: "GET", use: [scim_auth_middleware(config)]) do |ctx|
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
        ctx.json({schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults: resources.length, itemsPerPage: resources.length, startIndex: 1, Resources: resources})
      end
    end

    def scim_get_user_endpoint(config)
      Endpoint.new(path: "/scim/v2/Users/:userId", method: "GET", use: [scim_auth_middleware(config)]) do |ctx|
        user, account = scim_find_user_with_account!(ctx)
        ctx.json(scim_user_resource(user, account, ctx.context.base_url))
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
        encoded = ctx.headers["authorization"].to_s.sub(/\ABearer\s+/i, "")
        raise APIError.new("UNAUTHORIZED", message: "SCIM token is required") if encoded.empty?

        token, provider_id, organization_id = scim_decode_token(encoded)
        provider = scim_default_provider(config, token, provider_id, organization_id) ||
          ctx.context.adapter.find_one(
            model: "scimProvider",
            where: [{field: "providerId", value: provider_id}].tap { |where| where << {field: "organizationId", value: organization_id} if organization_id }
          )
        raise APIError.new("UNAUTHORIZED", message: "Invalid SCIM token") unless provider
        raise APIError.new("UNAUTHORIZED", message: "Invalid SCIM token") unless scim_token_matches?(ctx, config, token, provider.fetch("scimToken"))

        ctx.context.apply_plugin_context!(scim_provider: provider)
        nil
      end
    end

    def scim_required_roles(ctx, config)
      configured = config[:required_role] || config[:required_roles]
      return Array(configured).map(&:to_s) if configured

      organization = ctx.context.options.plugins.find { |plugin| plugin.id == "organization" }
      ["admin", organization&.options&.fetch(:creator_role, nil) || "owner"].uniq
    end

    def scim_has_required_role?(member_role, required_roles)
      required_roles.empty? || member_role.to_s.split(",").map(&:strip).any? { |role| required_roles.include?(role) }
    end

    def scim_provider_ownership_enabled?(config)
      ownership = normalize_hash(config[:provider_ownership] || {})
      ownership[:enabled] == true || ownership[:enabled].to_s == "true"
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

    def scim_organization_memberships(ctx, user_id)
      return {} unless scim_has_organization_plugin?(ctx)

      ctx.context.adapter.find_many(model: "member", where: [{field: "userId", value: user_id}]).each_with_object({}) do |member, result|
        result[member.fetch("organizationId")] = member.fetch("role").to_s.split(",").map(&:strip)
      end
    end

    def scim_assert_provider_access!(ctx, user_id, provider, required_roles)
      return unless provider

      if provider["organizationId"]
        raise APIError.new("FORBIDDEN", message: "Organization plugin is required to access this SCIM provider") unless scim_has_organization_plugin?(ctx)

        member = scim_find_organization_member(ctx, user_id, provider.fetch("organizationId"))
        raise APIError.new("FORBIDDEN", message: "You must be a member of the organization to access this provider") unless member
        raise APIError.new("FORBIDDEN", message: "Insufficient role for this operation") unless scim_has_required_role?(member.fetch("role"), required_roles)
      elsif !provider["userId"].to_s.empty? && provider["userId"] != user_id
        raise APIError.new("FORBIDDEN", message: "You must be the owner to access this provider")
      end
    end

    def scim_find_provider_connection!(ctx, provider_id)
      provider = ctx.context.adapter.find_one(model: "scimProvider", where: [{field: "providerId", value: provider_id.to_s}])
      raise APIError.new("NOT_FOUND", message: "SCIM provider not found") unless provider

      provider
    end

    def scim_provider_connection(provider)
      {
        "id" => provider.fetch("id"),
        "providerId" => provider.fetch("providerId"),
        "organizationId" => provider["organizationId"]
      }
    end

    def scim_store_token(ctx, config, token)
      storage = config[:store_scim_token]
      if storage == "hashed"
        Crypto.sha256(token)
      elsif storage == "encrypted"
        Crypto.symmetric_encrypt(key: ctx.context.secret, data: token)
      elsif storage.is_a?(Hash) && storage[:hash].respond_to?(:call)
        storage[:hash].call(token)
      elsif storage.is_a?(Hash) && storage[:encrypt].respond_to?(:call)
        storage[:encrypt].call(token)
      else
        token
      end
    end

    def scim_token_matches?(ctx, config, token, stored)
      storage = config[:store_scim_token]
      return Crypto.symmetric_decrypt(key: ctx.context.secret, data: stored) == token if storage == "encrypted"
      return storage[:decrypt].call(stored) == token if storage.is_a?(Hash) && storage[:decrypt].respond_to?(:call)

      !token.to_s.empty? && scim_store_token(ctx, config, token) == stored
    end

    def scim_decode_token(encoded)
      decoded = Base64.urlsafe_decode64(encoded.to_s)
      token, provider_id, *organization_parts = decoded.split(":")
      raise APIError.new("UNAUTHORIZED", message: "Invalid SCIM token") if token.to_s.empty? || provider_id.to_s.empty?

      [token, provider_id, organization_parts.join(":").then { |value| value.empty? ? nil : value }]
    rescue ArgumentError
      raise APIError.new("UNAUTHORIZED", message: "Invalid SCIM token")
    end

    def scim_default_provider(config, token, provider_id, organization_id)
      Array(config[:default_scim]).find do |provider|
        candidate = normalize_hash(provider)
        candidate[:provider_id].to_s == provider_id.to_s &&
          candidate[:scim_token].to_s == token.to_s &&
          candidate[:organization_id].to_s == organization_id.to_s
      end&.then do |provider|
        data = normalize_hash(provider)
        {"providerId" => data[:provider_id], "scimToken" => data[:scim_token], "organizationId" => data[:organization_id]}
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
      raise APIError.new("NOT_FOUND", message: "User not found") unless user && account

      [user, account]
    end

    def scim_user_update(body)
      {
        email: scim_primary_email(body)&.downcase,
        name: scim_display_name(body, body[:user_name].to_s),
        active: body.key?(:active) ? body[:active] : nil,
        externalId: body[:external_id]
      }.compact
    end

    def scim_apply_patch_value!(user, update, account_update, value, operation_name, path = nil)
      value.each do |key, nested_value|
        nested_key = Schema.storage_key(key)
        nested_path = path ? "#{path}.#{nested_key}" : nested_key
        if nested_value.is_a?(Hash)
          scim_apply_patch_value!(user, update, account_update, normalize_hash(nested_value), operation_name, nested_path)
        else
          scim_apply_patch_path!(user, update, account_update, nested_path, nested_value, operation_name)
        end
      end
    end

    def scim_apply_patch_path!(user, update, account_update, path, value, operation_name)
      remove = operation_name == "remove"
      normalized = "/" + path.to_s.sub(%r{\A/+}, "").tr(".", "/")
      case normalized
      when "/active"
        update[:active] = remove ? nil : value
      when "/userName"
        update[:email] = remove ? nil : value.to_s.downcase
      when "/externalId"
        account_update[:accountId] = remove ? nil : value
        update[:externalId] = remove ? nil : value
      when "/name/formatted"
        update[:name] = value unless remove
      when "/name/givenName"
        update[:name] = scim_full_name(user.fetch("email"), given_name: value, family_name: scim_family_name(update[:name] || user["name"])) unless remove
      when "/name/familyName"
        update[:name] = scim_full_name(user.fetch("email"), given_name: scim_given_name(update[:name] || user["name"]), family_name: value) unless remove
      end
    end

    def scim_display_name(body, fallback = nil)
      name = normalize_hash(body[:name] || {})
      return name[:formatted].to_s.strip unless name[:formatted].to_s.strip.empty?

      scim_full_name(fallback, given_name: name[:given_name], family_name: name[:family_name])
    end

    def scim_user_resource(user, account = nil, base_url = nil)
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        id: user.fetch("id"),
        userName: user.fetch("email"),
        externalId: account&.fetch("accountId", nil) || user["externalId"],
        displayName: user["name"],
        active: user.key?("active") ? user["active"] : true,
        name: {formatted: user["name"]},
        emails: [{primary: true, value: user.fetch("email")}],
        meta: {resourceType: "User", location: base_url ? "#{base_url}/scim/v2/Users/#{user.fetch("id")}" : nil}.compact
      }.compact
    end

    def scim_parse_filter(filter)
      match = filter.to_s.match(/\A\s*([^\s]+)\s+(eq|ne|co|sw|ew|pr)\s*(?:"([^"]*)"|([^\s]+))?\s*\z/i)
      raise APIError.new("BAD_REQUEST", message: "Invalid SCIM filter") unless match

      field = match[1]
      operator = match[2].downcase
      raise APIError.new("BAD_REQUEST", message: "The operator \"#{operator}\" is not supported") unless operator == "eq"
      raise APIError.new("BAD_REQUEST", message: "Invalid SCIM filter") unless %w[userName externalId].include?(field)

      [field, match[3] || match[4]]
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

    def scim_has_organization_plugin?(ctx)
      Array(ctx.context.options.plugins).any? { |plugin| plugin.id == "organization" }
    end

    def scim_create_org_membership(ctx, user_id, organization_id)
      return unless organization_id
      return if ctx.context.adapter.find_one(model: "member", where: [{field: "organizationId", value: organization_id}, {field: "userId", value: user_id}])

      ctx.context.adapter.create(model: "member", data: {userId: user_id, organizationId: organization_id, role: "member", createdAt: Time.now})
    end

    def scim_account_id(body)
      body[:external_id] || body[:user_name]
    end

    def scim_primary_email(body)
      primary = Array(body[:emails]).find { |email| normalize_hash(email)[:primary] }
      first = Array(body[:emails]).first
      normalize_hash(primary || first)[:value] || body[:user_name]
    end

    def scim_full_name(fallback, given_name:, family_name:)
      name = [given_name, family_name].compact.join(" ").strip
      name.empty? ? fallback.to_s : name
    end

    def scim_given_name(name)
      parts = name.to_s.split
      (parts.length > 1) ? parts[0...-1].join(" ") : name.to_s
    end

    def scim_family_name(name)
      parts = name.to_s.split
      (parts.length > 1) ? parts[1..].join(" ") : ""
    end
  end
end
