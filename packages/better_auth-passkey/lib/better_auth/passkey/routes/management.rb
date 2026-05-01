# frozen_string_literal: true

module BetterAuth
  module Passkey
    module Routes
      module Management
        module_function

        def list_passkeys_endpoint
          Endpoint.new(path: "/passkey/list-user-passkeys", method: "GET") do |ctx|
            session = BetterAuth::Routes.current_session(ctx)
            passkeys = ctx.context.adapter.find_many(model: "passkey", where: [{field: "userId", value: session.fetch(:user).fetch("id")}])
            ctx.json(passkeys.map { |passkey| Credentials.wire(passkey) })
          end
        end

        def delete_passkey_endpoint
          Endpoint.new(path: "/passkey/delete-passkey", method: "POST") do |ctx|
            session = BetterAuth::Routes.current_session(ctx)
            body = Utils.normalize_hash(ctx.body)
            Utils.require_string!(body, :id)
            passkey = ctx.context.adapter.find_one(model: "passkey", where: [{field: "id", value: body[:id]}])
            raise APIError.new("NOT_FOUND", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("PASSKEY_NOT_FOUND")) unless passkey
            unless passkey.fetch("userId") == session.fetch(:user).fetch("id")
              raise APIError.new("UNAUTHORIZED", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("PASSKEY_NOT_FOUND"))
            end

            ctx.context.adapter.delete(model: "passkey", where: [{field: "id", value: passkey.fetch("id")}])
            ctx.json({status: true})
          end
        end

        def update_passkey_endpoint
          Endpoint.new(path: "/passkey/update-passkey", method: "POST") do |ctx|
            session = BetterAuth::Routes.current_session(ctx)
            body = Utils.normalize_hash(ctx.body)
            Utils.require_string!(body, :id)
            unless body.key?(:name) && body[:name].is_a?(String)
              raise APIError.new("BAD_REQUEST", message: BASE_ERROR_CODES.fetch("VALIDATION_ERROR"))
            end

            passkey = ctx.context.adapter.find_one(model: "passkey", where: [{field: "id", value: body[:id]}])
            raise APIError.new("NOT_FOUND", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("PASSKEY_NOT_FOUND")) unless passkey
            if passkey.fetch("userId") != session.fetch(:user).fetch("id")
              raise APIError.new("UNAUTHORIZED", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"))
            end

            updated = ctx.context.adapter.update(
              model: "passkey",
              where: [{field: "id", value: body[:id]}],
              update: {name: body[:name].to_s}
            )
            raise APIError.new("INTERNAL_SERVER_ERROR", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("FAILED_TO_UPDATE_PASSKEY")) unless updated

            ctx.json({passkey: Credentials.wire(updated)})
          end
        end
      end
    end
  end
end
