# frozen_string_literal: true

module BetterAuth
  module Plugins
    module OrganizationSchema
      module_function

      def build(config)
        schema = {
          organization: {
            fields: {
              name: {type: "string", required: true, sortable: true},
              slug: {type: "string", required: true, unique: true, sortable: true},
              logo: {type: "string", required: false},
              metadata: {type: "string", required: false},
              createdAt: {type: "date", required: true, default_value: -> { Time.now }},
              updatedAt: {type: "date", required: false, on_update: -> { Time.now }}
            }
          },
          member: {
            fields: {
              organizationId: {type: "string", required: true, references: {model: "organization", field: "id"}, index: true},
              userId: {type: "string", required: true, references: {model: "user", field: "id"}, index: true},
              role: {type: "string", required: true, default_value: "member"},
              createdAt: {type: "date", required: true, default_value: -> { Time.now }}
            }
          },
          invitation: {
            fields: {
              organizationId: {type: "string", required: true, references: {model: "organization", field: "id"}, index: true},
              email: {type: "string", required: true, sortable: true},
              role: {type: "string", required: true, sortable: true},
              status: {type: "string", required: true, sortable: true, default_value: "pending"},
              expiresAt: {type: "date", required: false},
              createdAt: {type: "date", required: true, default_value: -> { Time.now }},
              inviterId: {type: "string", required: true, references: {model: "user", field: "id"}},
              teamId: {type: "string", required: false, sortable: true}
            }
          },
          session: {
            fields: {
              activeOrganizationId: {type: "string", required: false}
            }
          }
        }

        if truthy?(config.dig(:teams, :enabled))
          schema[:team] = {
            fields: {
              name: {type: "string", required: true},
              organizationId: {type: "string", required: true, references: {model: "organization", field: "id"}, index: true},
              createdAt: {type: "date", required: true, default_value: -> { Time.now }},
              updatedAt: {type: "date", required: false, on_update: -> { Time.now }}
            }
          }
          schema[:teamMember] = {
            fields: {
              teamId: {type: "string", required: true, references: {model: "team", field: "id"}, index: true},
              userId: {type: "string", required: true, references: {model: "user", field: "id"}, index: true},
              createdAt: {type: "date", required: false, default_value: -> { Time.now }}
            }
          }
          schema[:session][:fields][:activeTeamId] = {type: "string", required: false}
        end

        if truthy?(config.dig(:dynamic_access_control, :enabled))
          schema[:organizationRole] = {
            fields: {
              organizationId: {type: "string", required: true, references: {model: "organization", field: "id"}, index: true},
              role: {type: "string", required: true},
              permission: {type: "string", required: true},
              createdAt: {type: "date", required: true, default_value: -> { Time.now }},
              updatedAt: {type: "date", required: false, on_update: -> { Time.now }}
            }
          }
        end

        merge_custom_schema(schema, config[:schema])
      end

      def merge_custom_schema(base, custom)
        return base unless custom.is_a?(Hash)

        custom.each_with_object(base) do |(raw_model, raw_table), result|
          model = Schema.storage_key(raw_model).to_sym
          table = raw_table || {}
          result[model] ||= {fields: {}}
          result[model][:model_name] = table[:model_name] || table["modelName"] || table["model_name"] if table[:model_name] || table["modelName"] || table["model_name"]
          fields = table[:fields] || table["fields"] || {}
          additional = table[:additional_fields] || table["additionalFields"] || table["additional_fields"] || {}
          result[model][:fields] = (result[model][:fields] || {}).merge(storage_fields(fields)).merge(storage_fields(additional))
        end
      end

      def truthy?(value)
        value == true || value.to_s == "true"
      end
    end
  end
end
