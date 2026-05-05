# frozen_string_literal: true

require "securerandom"
require "time"
require "sequel"

module BetterAuth
  module Hanami
    class SequelAdapter < BetterAuth::Adapters::Base
      attr_reader :connection

      def self.from_hanami(options, container: nil)
        if container.nil? && defined?(::Hanami) && ::Hanami.respond_to?(:app)
          container = ::Hanami.app
        end
        return memory_fallback(options) unless container

        from_container(container, options)
      end

      def self.from_container(container, options)
        gateway = if container.respond_to?(:key?) && container.key?("db.gateway")
          container["db.gateway"]
        elsif container.respond_to?(:[]) && safe_fetch(container, "db.gateway")
          container["db.gateway"]
        end
        return memory_fallback(options) unless gateway

        connection = gateway.respond_to?(:connection) ? gateway.connection : gateway
        new(options, connection: connection)
      end

      def self.safe_fetch(container, key)
        container[key]
      rescue KeyError
        nil
      end

      def self.memory_fallback(options)
        Kernel.warn(
          "[better_auth-hanami] SequelAdapter: using BetterAuth::Adapters::Memory " \
          "(no Hanami container or db.gateway). Persisted auth data will not survive process restart."
        )
        BetterAuth::Adapters::Memory.new(options)
      end

      def initialize(options, connection:)
        super(options)
        @connection = connection
      end

      def create(model:, data:, force_allow_id: false)
        model = model.to_s
        input = transform_input(model, data, "create", force_allow_id)
        table_dataset(model).insert(physical_attributes(model, input))
        find_one(model: model, where: [{field: "id", value: input.fetch("id")}])
      end

      def find_one(model:, where: [], select: nil, join: nil)
        find_many(model: model, where: where, select: select, join: join, limit: 1).first
      end

      def find_many(model:, where: [], sort_by: nil, limit: nil, offset: nil, select: nil, join: nil)
        model = model.to_s
        dataset = table_dataset(model)
        dataset = apply_where(model, dataset, where || [])
        dataset = apply_select(model, dataset, select) if select
        dataset = apply_order(model, dataset, sort_by) if sort_by
        dataset = dataset.limit(Integer(limit)) if limit
        dataset = dataset.offset(Integer(offset)) if offset

        records = dataset.all.map { |row| normalize_record(model, row) }
        attach_joins(model, records, join)
      end

      def update(model:, where:, update:)
        model = model.to_s
        existing = find_one(model: model, where: where, select: ["id"])
        return nil unless existing

        update_many(model: model, where: where, update: update)
        find_one(model: model, where: [{field: "id", value: existing.fetch("id")}])
      end

      def update_many(model:, where:, update:, returning: false)
        model = model.to_s
        existing = returning ? find_many(model: model, where: where, select: ["id"]) : []
        attributes = physical_attributes(model, transform_input(model, update, "update", true))
        apply_where(model, table_dataset(model), where || []).update(attributes)
        return unless returning

        existing.map { |record| find_one(model: model, where: [{field: "id", value: record.fetch("id")}]) }
      end

      def delete(model:, where:)
        delete_many(model: model, where: where)
        nil
      end

      def delete_many(model:, where:)
        model = model.to_s
        apply_where(model, table_dataset(model), where || []).delete
      end

      def count(model:, where: nil)
        model = model.to_s
        apply_where(model, table_dataset(model), where || []).count
      end

      def transaction
        connection.transaction { yield self }
      end

      private

      def table_dataset(model)
        connection[table_for(model).to_sym]
      end

      def apply_where(model, dataset, where)
        expression = Array(where).each_with_index.reduce(nil) do |combined, (clause, index)|
          current = where_expression(model, clause)
          next current if index.zero?

          connector = fetch_key(clause, :connector).to_s.upcase
          (connector == "OR") ? Sequel.|(combined, current) : Sequel.&(combined, current)
        end
        expression ? dataset.where(expression) : dataset
      end

      def where_expression(model, clause)
        field = storage_key(fetch_key(clause, :field))
        column = storage_field(model, field)
        identifier = Sequel[column.to_sym]
        operator = (fetch_key(clause, :operator) || "eq").to_s
        value = fetch_key(clause, :value)

        case operator
        when "in" then {column.to_sym => Array(value)}
        when "not_in" then Sequel.~(column.to_sym => Array(value))
        when "ne" then Sequel.~(column.to_sym => value)
        when "gt" then identifier > value
        when "gte" then identifier >= value
        when "lt" then identifier < value
        when "lte" then identifier <= value
        when "contains" then Sequel.like(identifier, "%#{value}%")
        when "starts_with" then Sequel.like(identifier, "#{value}%")
        when "ends_with" then Sequel.like(identifier, "%#{value}")
        else {column.to_sym => value}
        end
      end

      def apply_select(model, dataset, select)
        dataset.select(*Array(select).map { |field| storage_field(model, storage_key(field)).to_sym })
      end

      def apply_order(model, dataset, sort_by)
        column = storage_field(model, storage_key(fetch_key(sort_by, :field))).to_sym
        direction = (fetch_key(sort_by, :direction).to_s.downcase == "desc") ? Sequel.desc(column) : column
        dataset.order(direction)
      end

      def attach_joins(model, records, join)
        return records unless join

        records.each do |record|
          join.each_key do |join_model|
            join_model = join_model.to_s
            case [model.to_s, join_model]
            when ["session", "user"], ["account", "user"]
              record[join_model] = find_one(model: join_model, where: [{field: "id", value: record["userId"]}])
            when ["user", "account"]
              record[join_model] = find_many(model: "account", where: [{field: "userId", value: record["id"]}])
            end
          end
        end
        records
      end

      def transform_input(model, data, action, force_allow_id)
        fields = schema_for(model).fetch(:fields)
        input = stringify_keys(data)
        output = {}

        fields.each do |field, attributes|
          next if field == "id" && input.key?(field) && !force_allow_id

          value_provided = input.key?(field)
          value = input[field]
          if value_provided && attributes[:input] == false && value && !force_allow_id
            raise APIError.new("BAD_REQUEST", message: "#{field} is not allowed to be set")
          end

          if !value_provided && action == "create" && attributes.key?(:default_value)
            value = resolve_default(attributes[:default_value])
            value_provided = true
          elsif !value_provided && action == "update" && attributes[:on_update]
            value = resolve_default(attributes[:on_update])
            value_provided = true
          end
          if !value_provided && action == "create" && attributes[:required]
            raise APIError.new("BAD_REQUEST", message: "#{field} is required") unless field == "id"
          end
          output[field] = coerce_value(value, attributes) if value_provided
        end

        output["id"] = generated_id if action == "create" && !output.key?("id")
        output
      end

      def physical_attributes(model, logical)
        logical.each_with_object({}) do |(field, value), attributes|
          attributes[storage_field(model, field).to_sym] = value
        end
      end

      def normalize_record(model, row)
        return nil unless row

        schema_for(model).fetch(:fields).each_with_object({}) do |(field, attributes), output|
          column = (attributes[:field_name] || physical_name(field)).to_sym
          output[field] = coerce_output_value(row[column], attributes) if row.key?(column)
        end
      end

      def table_for(model)
        schema_for(model).fetch(:model_name)
      end

      def schema_for(model)
        BetterAuth::Schema.auth_tables(options).fetch(model.to_s)
      end

      def storage_field(model, field)
        schema_for(model).fetch(:fields).fetch(field.to_s).fetch(:field_name, physical_name(field))
      end

      def generated_id
        generator = options.advanced.dig(:database, :generate_id)
        return generator.call.to_s if generator.respond_to?(:call)
        return SecureRandom.uuid if generator == "uuid"

        SecureRandom.hex(16)
      end

      def resolve_default(default)
        default.respond_to?(:call) ? default.call : default
      end

      def coerce_value(value, attributes)
        return value if value.nil?
        return Time.parse(value) if attributes[:type] == "date" && value.is_a?(String)

        value
      end

      def coerce_output_value(value, attributes)
        return value if value.nil?
        return coerce_boolean(value) if attributes[:type] == "boolean"
        return Time.parse(value.to_s) if attributes[:type] == "date" && !value.is_a?(Time)

        value
      end

      def coerce_boolean(value)
        return value if value == true || value == false
        return false if value == 0 || value.to_s == "0" || value.to_s.downcase == "f" || value.to_s.downcase == "false"
        return true if value == 1 || value.to_s == "1" || value.to_s.downcase == "t" || value.to_s.downcase == "true"

        value
      end

      def stringify_keys(data)
        data.each_with_object({}) do |(key, value), result|
          result[storage_key(key)] = value
        end
      end

      def fetch_key(hash, key)
        [key, key.to_s, storage_key(key), storage_key(key).to_sym].each do |candidate|
          return hash[candidate] if hash.key?(candidate)
        end
        nil
      end

      def storage_key(value)
        parts = physical_name(value).split("_")
        ([parts.first] + parts.drop(1).map(&:capitalize)).join
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
