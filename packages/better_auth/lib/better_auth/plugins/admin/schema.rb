# frozen_string_literal: true

module BetterAuth
  module Plugins
    module AdminSchema
      module_function

      def build(custom = nil)
        schema = {
          user: {
            fields: {
              role: {type: "string", required: false, input: false},
              banned: {type: "boolean", required: false, input: false, default_value: false},
              banReason: {type: "string", required: false, input: false},
              banExpires: {type: "date", required: false, input: false}
            }
          },
          session: {
            fields: {
              impersonatedBy: {type: "string", required: false}
            }
          }
        }
        OrganizationSchema.merge_custom_schema(schema, custom)
      end
    end
  end
end
