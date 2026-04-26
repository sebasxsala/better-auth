# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def additional_fields(schema = {})
      config = normalize_hash(schema)
      user_fields = storage_fields(config[:user] || {})
      session_fields = storage_fields(config[:session] || {})

      Plugin.new(
        id: "additional-fields",
        schema: {
          user: {fields: user_fields},
          session: {fields: session_fields}
        },
        init: lambda do |_context|
          {
            options: {
              user: {additional_fields: user_fields},
              session: {additional_fields: session_fields}
            }
          }
        end
      )
    end
  end
end
