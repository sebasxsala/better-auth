# frozen_string_literal: true

module BetterAuth
  module APIKey
    module Routes
      module ListAPIKeys
        UPSTREAM_SOURCE = "upstream/packages/api-key/src/routes/list-api-keys.ts"

        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/api-key/list", method: "GET") do |ctx|
            session = BetterAuth::Routes.current_session(ctx)
            query = BetterAuth::Plugins.normalize_hash(ctx.query)
            BetterAuth::Plugins.api_key_validate_list_query!(query)
            configs = query[:config_id] ? [BetterAuth::Plugins.api_key_resolve_config(ctx.context, config, query[:config_id])] : config.fetch(:configurations, [config])
            reference_id = query[:organization_id] || session[:user]["id"]
            expected_reference = query[:organization_id] ? "organization" : "user"
            BetterAuth::Plugins.api_key_check_org_permission!(ctx, session[:user]["id"], reference_id, "read") if query[:organization_id]
            records = configs.flat_map { |entry| BetterAuth::Plugins.api_key_list_for_reference(ctx, reference_id, entry) }.uniq { |record| record["id"] }
            records = records.select do |record|
              record_config = BetterAuth::Plugins.api_key_resolve_config(ctx.context, config, BetterAuth::Plugins.api_key_record_config_id(record))
              record_config[:references].to_s == expected_reference &&
                BetterAuth::Plugins.api_key_record_reference_id(record) == reference_id &&
                (!query[:config_id] || BetterAuth::Plugins.api_key_config_id_matches?(BetterAuth::Plugins.api_key_record_config_id(record), query[:config_id]))
            end
            total = records.length
            records = BetterAuth::Plugins.api_key_sort_records(records, query[:sort_by], query[:sort_direction])
            offset = query.key?(:offset) ? query[:offset].to_i : nil
            limit = query.key?(:limit) ? query[:limit].to_i : nil
            records = records.drop(offset) if offset
            records = records.first(limit) if limit
            records.each { |record| BetterAuth::Plugins.api_key_delete_expired(ctx.context, BetterAuth::Plugins.api_key_resolve_config(ctx.context, config, BetterAuth::Plugins.api_key_record_config_id(record))) }
            api_keys = records.map do |record|
              record_config = BetterAuth::Plugins.api_key_resolve_config(ctx.context, config, BetterAuth::Plugins.api_key_record_config_id(record))
              BetterAuth::Plugins.api_key_public(BetterAuth::Plugins.api_key_migrate_legacy_metadata(ctx, record, record_config), include_key_field: false)
            end
            ctx.json({apiKeys: api_keys, total: total, limit: limit, offset: offset})
          end
        end
      end
    end
  end
end
