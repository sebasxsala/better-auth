# frozen_string_literal: true

module BetterAuth
  module Rails
    class ActiveRecordAdapter < BetterAuth::Adapters::Base
      begin
        require "active_record" unless defined?(::ActiveRecord)
      rescue LoadError
        # ActiveRecord is required only when the adapter is instantiated in a Rails app.
      end

      if defined?(::ActiveRecord::Base)
        class ApplicationRecord < ::ActiveRecord::Base
          self.abstract_class = true
        end
      else
        class ApplicationRecord
        end
      end

      attr_reader :connection

      def initialize(options, connection: nil)
        super(options)
        @connection = connection || ::ActiveRecord::Base
        @models = {}
      end

      def create(model:, data:, force_allow_id: false)
        model = model.to_s
        input = transform_input(model, data, "create", force_allow_id)
        record = model_class(model).create!(physical_attributes(model, input))
        normalize_record(model, record)
      end

      def find_one(model:, where: [], select: nil, join: nil)
        find_many(model: model, where: where, select: select, join: join, limit: 1).first
      end

      def find_many(model:, where: [], sort_by: nil, limit: nil, offset: nil, select: nil, join: nil)
        model = model.to_s
        relation = relation_for(model, where: where, sort_by: sort_by, limit: limit, offset: offset, select: select, join: join)
        records = relation.map { |record| normalize_record(model, record, join: join) }
        collection_join?(model, join) ? aggregate_collection_joins(records) : records
      end

      def update(model:, where:, update:)
        model = model.to_s
        record = relation_for(model, where: where).first
        return nil unless record

        record.update!(physical_attributes(model, transform_input(model, update, "update", true)))
        normalize_record(model, record)
      end

      def update_many(model:, where:, update:, returning: false)
        model = model.to_s
        attributes = physical_attributes(model, transform_input(model, update, "update", true))
        relation = relation_for(model, where: where)
        if returning
          relation.map do |record|
            record.update!(attributes)
            normalize_record(model, record)
          end
        else
          relation.update_all(attributes)
        end
      end

      def delete(model:, where:)
        model = model.to_s
        record = relation_for(model, where: where).first
        record&.destroy!
        nil
      end

      def delete_many(model:, where:)
        relation_for(model.to_s, where: where).delete_all
      end

      def count(model:, where: nil)
        relation_for(model.to_s, where: where || []).count
      end

      def transaction
        connection.connection.transaction { yield self }
      end

      private

      def model_class(model)
        model = model.to_s
        return @models[model] if @models.key?(model)

        klass = Class.new(ApplicationRecord)
        model_namespace.const_set(class_name_for(model), klass)
        klass.table_name = table_for(model) if klass.respond_to?(:table_name=)
        klass.primary_key = storage_field(model, "id") if klass.respond_to?(:primary_key=)
        @models[model] = klass
        define_join_associations(model, klass)
        klass
      end

      def relation_for(model, where:, sort_by: nil, limit: nil, offset: nil, select: nil, join: nil)
        relation = model_class(model).all
        relation = apply_where(model, relation, where || [])
        relation = apply_select(model, relation, select) if select
        relation = apply_join_includes(model, relation, join) if join
        relation = apply_order(model, relation, sort_by) if sort_by
        relation = relation.limit(Integer(limit)) if limit
        relation = relation.offset(Integer(offset)) if offset
        relation
      end

      def apply_where(model, relation, where)
        Array(where).reduce(relation) do |scope, clause|
          field = storage_key(fetch_key(clause, :field))
          column = storage_field(model, field)
          operator = (fetch_key(clause, :operator) || "eq").to_s
          value = fetch_key(clause, :value)
          apply_operator(scope, column, operator, value)
        end
      end

      def apply_operator(scope, column, operator, value)
        case operator
        when "in" then scope.where(column => Array(value))
        when "not_in" then scope.where.not(column => Array(value))
        when "ne" then scope.where.not(column => value)
        when "gt" then scope.where("#{column} > ?", value)
        when "gte" then scope.where("#{column} >= ?", value)
        when "lt" then scope.where("#{column} < ?", value)
        when "lte" then scope.where("#{column} <= ?", value)
        when "contains" then scope.where("#{column} LIKE ?", "%#{value}%")
        when "starts_with" then scope.where("#{column} LIKE ?", "#{value}%")
        when "ends_with" then scope.where("#{column} LIKE ?", "%#{value}")
        else scope.where(column => value)
        end
      end

      def apply_select(model, relation, select)
        columns = Array(select).map { |field| storage_field(model, storage_key(field)) }
        relation.select(*columns)
      end

      def apply_order(model, relation, sort_by)
        field = storage_key(fetch_key(sort_by, :field))
        direction = (fetch_key(sort_by, :direction).to_s.downcase == "desc") ? :desc : :asc
        relation.order(storage_field(model, field) => direction)
      end

      def transform_input(model, data, action, force_allow_id)
        fields = schema_for(model).fetch(:fields)
        input = stringify_keys(data)
        output = {}
        fields.each do |field, attributes|
          next if field == "id" && input.key?(field) && !force_allow_id

          value_provided = input.key?(field)
          value = input[field]
          if !value_provided && action == "create" && attributes.key?(:default_value)
            value = resolve_default(attributes[:default_value])
            value_provided = true
          elsif !value_provided && action == "update" && attributes[:on_update]
            value = resolve_default(attributes[:on_update])
            value_provided = true
          end
          output[field] = value if value_provided
        end
        output["id"] = SecureRandom.urlsafe_base64(16) if action == "create" && !output.key?("id")
        output
      end

      def physical_attributes(model, logical)
        logical.each_with_object({}) do |(field, value), attributes|
          attributes[storage_field(model, field)] = value
        end
      end

      def normalize_record(model, record, join: nil)
        return nil unless record

        attributes = record.respond_to?(:attributes) ? record.attributes : record
        normalized = schema_for(model).fetch(:fields).each_with_object({}) do |(field, config), output|
          column = config[:field_name] || physical_name(field)
          output[field] = attributes[column] if attributes.key?(column)
        end
        attach_joins(model, normalized, record, join)
      end

      def attach_joins(model, normalized, record, join)
        return normalized unless join

        join.each_key do |join_model|
          join_model = join_model.to_s
          definition = join_definition(model, join_model)
          next unless definition

          association = definition.fetch(:association)
          next unless record.respond_to?(association)

          joined = record.public_send(association)
          normalized[join_model] = if definition[:collection]
            Array(joined).map { |joined_record| normalize_record(join_model, joined_record) }
          else
            normalize_record(join_model, joined)
          end
        end
        normalized
      end

      def apply_join_includes(model, relation, join)
        associations = join.filter_map do |join_model, _enabled|
          join_definition(model, join_model.to_s)&.fetch(:association)
        end
        return relation if associations.empty? || !relation.respond_to?(:includes)

        relation.includes(*associations)
      end

      def define_join_associations(model, klass)
        schema_models.each_key do |join_model|
          next if join_model == model

          definition = safe_join_definition(model, join_model)
          next unless definition

          association = definition.fetch(:association)
          next if association_defined?(klass, association)

          if definition[:owner] == :base && definition[:collection]
            next unless klass.respond_to?(:has_many)

            klass.has_many(
              association,
              class_name: model_class(join_model).name,
              foreign_key: storage_field(join_model, definition.fetch(:to)),
              primary_key: storage_field(model, definition.fetch(:from))
            )
          elsif definition[:owner] == :base
            next unless klass.respond_to?(:has_one)

            klass.has_one(
              association,
              class_name: model_class(join_model).name,
              foreign_key: storage_field(join_model, definition.fetch(:to)),
              primary_key: storage_field(model, definition.fetch(:from))
            )
          else
            next unless klass.respond_to?(:belongs_to)

            klass.belongs_to(
              association,
              class_name: model_class(join_model).name,
              foreign_key: storage_field(model, definition.fetch(:from)),
              primary_key: storage_field(join_model, definition.fetch(:to)),
              optional: true
            )
          end
        end
      end

      def join_definition(model, join_model)
        inferred_join_config(model.to_s, join_model.to_s).merge(association: join_model.to_sym)
      end

      def safe_join_definition(model, join_model)
        join_definition(model, join_model)
      rescue BetterAuth::Error
        nil
      end

      def inferred_join_config(model, join_model)
        foreign_keys = schema_for(join_model).fetch(:fields).select do |_field, attributes|
          reference_model_matches?(attributes, model)
        end

        unless foreign_keys.empty?
          raise BetterAuth::Error, "Multiple foreign keys found for model #{join_model} and base model #{model} while performing join operation. Only one foreign key is supported." if foreign_keys.length > 1

          foreign_key, attributes = foreign_keys.first
          reference = attributes.fetch(:references)
          unique = attributes[:unique] == true
          return {
            from: reference.fetch(:field).to_s,
            to: foreign_key,
            collection: !unique,
            owner: :base
          }
        end

        foreign_keys = schema_for(model).fetch(:fields).select do |_field, attributes|
          reference_model_matches?(attributes, join_model)
        end

        raise BetterAuth::Error, "No foreign key found for model #{join_model} and base model #{model} while performing join operation." if foreign_keys.empty?
        raise BetterAuth::Error, "Multiple foreign keys found for model #{join_model} and base model #{model} while performing join operation. Only one foreign key is supported." if foreign_keys.length > 1

        foreign_key, attributes = foreign_keys.first
        reference = attributes.fetch(:references)
        {
          from: foreign_key,
          to: reference.fetch(:field).to_s,
          collection: false,
          owner: :join
        }
      end

      def reference_model_matches?(attributes, model)
        reference = attributes[:references]
        return false unless reference

        reference_model = reference[:model] || reference["model"]
        reference_model.to_s == model.to_s || reference_model.to_s == table_for(model)
      end

      def association_defined?(klass, association)
        klass.respond_to?(:reflect_on_association) && klass.reflect_on_association(association)
      end

      def schema_models
        BetterAuth::Schema.auth_tables(options)
      end

      def model_namespace
        @model_namespace ||= BetterAuth::Rails.const_set("ActiveRecordAdapterModels#{object_id}", Module.new)
      end

      def class_name_for(model)
        physical_name(model).split("_").map(&:capitalize).join
      end

      def collection_join?(model, join)
        model == "user" && join&.keys&.any? { |join_model| join_model.to_s == "account" }
      end

      def aggregate_collection_joins(records)
        records
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

      def stringify_keys(value)
        return {} unless value.respond_to?(:each)

        value.each_with_object({}) { |(key, object), result| result[storage_key(key)] = object }
      end

      def fetch_key(hash, key)
        [key, key.to_s, storage_key(key), storage_key(key).to_sym].each do |candidate|
          return hash[candidate] if hash.key?(candidate)
        end
        nil
      end

      def storage_key(value)
        BetterAuth::Schema.send(:storage_key, value)
      end

      def physical_name(value)
        BetterAuth::Schema.send(:physical_name, value)
      end

      def resolve_default(value)
        value.respond_to?(:call) ? value.call : value
      end
    end
  end
end
