# frozen_string_literal: true

module BetterAuth
  module APIKey
    module Routes
      module VerifyAPIKey
        UPSTREAM_SOURCE = "upstream/packages/api-key/src/routes/verify-api-key.ts"

        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/api-key/verify", method: "POST") do |ctx|
            body = BetterAuth::Plugins.normalize_hash(ctx.body)
            resolved_config = BetterAuth::Plugins.api_key_resolve_config(ctx.context, config, body[:config_id])
            key = body[:key]
            if key.to_s.empty?
              raise BetterAuth::APIError.new(
                "FORBIDDEN",
                message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"],
                code: "INVALID_API_KEY"
              )
            end

            if resolved_config[:custom_api_key_validator].respond_to?(:call) && !resolved_config[:custom_api_key_validator].call({ctx: ctx, key: key})
              ctx.json({valid: false, error: {message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"], code: "KEY_NOT_FOUND"}, key: nil})
            else
              record = BetterAuth::Plugins.api_key_validate!(ctx, key, resolved_config, permissions: body[:permissions])
              record_config = BetterAuth::Plugins.api_key_resolve_config(ctx.context, config, BetterAuth::Plugins.api_key_record_config_id(record))
              BetterAuth::Plugins.api_key_schedule_cleanup(ctx, record_config)
              ctx.json({valid: true, error: nil, key: BetterAuth::Plugins.api_key_public(record, include_key_field: false)})
            end
          rescue BetterAuth::APIError => error
            ctx.context.logger.error("Failed to validate API key: #{error.message}") if ctx.context.logger.respond_to?(:error)
            ctx.json({valid: false, error: BetterAuth::Plugins.api_key_error_payload(error), key: nil})
          rescue => error
            ctx.context.logger.error("Failed to validate API key: #{error.message}") if ctx.context.logger.respond_to?(:error)
            ctx.json({valid: false, error: {message: BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"], code: "INVALID_API_KEY"}, key: nil})
          end
        end
      end
    end
  end
end
