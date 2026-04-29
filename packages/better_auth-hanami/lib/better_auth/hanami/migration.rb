# frozen_string_literal: true

module BetterAuth
  module Hanami
    module Migration
      module_function

      def render(options)
        tables = BetterAuth::Schema.auth_tables(options)
        lines = [
          "# frozen_string_literal: true",
          "",
          "require \"date\"",
          "require \"rom-sql\"",
          "",
          "ROM::SQL.migration do",
          "  change do"
        ]
        tables.each_value { |table| lines.concat(create_table_lines(table, options)) }
        lines.concat(["  end", "end", ""])
        lines.join("\n")
      end

      def create_table_lines(table, options)
        table_name = table.fetch(:model_name)
        lines = ["", "    create_table :#{table_name} do"]
        table.fetch(:fields).each do |logical_field, attributes|
          lines << column_line(logical_field, attributes, options)
        end
        lines << "      primary_key [:id]" if table.fetch(:fields).key?("id")
        table.fetch(:fields).each do |logical_field, attributes|
          index = index_line(logical_field, attributes)
          lines << index if index
        end
        lines << "    end"
        lines
      end

      def column_line(logical_field, attributes, options)
        column = attributes[:field_name] || physical_name(logical_field)
        reference = attributes[:references]
        if reference
          target = foreign_key_target(reference.fetch(:model), options)
          parts = ["foreign_key :#{column}, :#{target}", "type: #{hanami_type(attributes)}"]
          parts << "null: false" if attributes[:required]
          parts << "on_delete: :#{reference[:on_delete]}" if reference[:on_delete]
          return "      #{parts.join(", ")}"
        end

        parts = ["column :#{column}", hanami_type(attributes)]
        parts << "null: false" if attributes[:required]
        default = default_value(attributes)
        parts << "default: #{default}" unless default.nil?
        "      #{parts.join(", ")}"
      end

      def index_line(logical_field, attributes)
        return unless attributes[:unique] || attributes[:index]

        column = attributes[:field_name] || physical_name(logical_field)
        unique = attributes[:unique] ? ", unique: true" : ""
        "      index :#{column}#{unique}"
      end

      def hanami_type(attributes)
        case attributes[:type]
        when "boolean" then "TrueClass"
        when "date" then "DateTime"
        when "number" then attributes[:bigint] ? ":Bignum" : "Integer"
        else "String"
        end
      end

      def default_value(attributes)
        default = attributes[:default_value]
        return if default.respond_to?(:call)

        case default
        when true then "true"
        when false then "false"
        when Numeric then default.to_s
        when String then default.inspect
        end
      end

      def foreign_key_target(model, options)
        tables = BetterAuth::Schema.auth_tables(options)
        tables.fetch(model.to_s, nil)&.fetch(:model_name) || model
      end

      def physical_name(value)
        value.to_s
          .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
          .tr("-", "_")
          .downcase
      end
    end
  end
end
