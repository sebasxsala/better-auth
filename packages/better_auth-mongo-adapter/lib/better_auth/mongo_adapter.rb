# frozen_string_literal: true

require "better_auth"
require "mongo"
require "securerandom"
require "time"

module BetterAuth
  module Adapters
    class MongoDB < Base
      attr_reader :database, :client, :use_plural

      def initialize(options = nil, database:, client: nil, transaction: nil, use_plural: false)
        require "mongo" unless database

        super(options || Configuration.new(secret: Configuration::DEFAULT_SECRET, database: :memory))
        @database = database
        @client = client
        @transaction_enabled = transaction.nil? ? !client.nil? : !!transaction
        @use_plural = !!use_plural
        @session = nil
      end

      def create(model:, data:, force_allow_id: false)
        model = model.to_s
        record = transform_input(model, data, "create", force_allow_id)
        document = to_document(model, record)
        collection_for(model).insert_one(document, session_options)
        from_document(model, document)
      end

      def find_one(model:, where: [], select: nil, join: nil)
        find_many(model: model, where: where, select: select, join: join, limit: 1).first
      end

      def find_many(model:, where: [], sort_by: nil, limit: nil, offset: nil, select: nil, join: nil)
        model = model.to_s
        records = documents_for(model)
          .select { |document| matches_where?(model, document, where || []) }
          .map { |document| from_document(model, document) }
        records = records.map { |record| apply_join(model, record, join) } if join
        records = sort_records(records, sort_by) if sort_by
        records = records.drop(offset.to_i) if offset
        records = records.first(limit.to_i) if limit
        records = records.map { |record| select_fields(record, select, join) } if select && !select.empty?
        records
      end

      def update(model:, where:, update:)
        model = model.to_s
        records = update_matching(model, where || [], update, first_only: true)
        records.first
      end

      def update_many(model:, where:, update:)
        update_matching(model.to_s, where || [], update, first_only: false).length
      end

      def delete(model:, where:)
        delete_many(model: model, where: where, first_only: true)
        nil
      end

      def delete_many(model:, where:, first_only: false)
        model = model.to_s
        documents = documents_for(model)
        matches = documents.select { |document| matches_where?(model, document, where || []) }
        matches = matches.first(1) if first_only
        ids = matches.map { |document| document["_id"] }
        remaining = documents.reject { |document| ids.include?(document["_id"]) }
        replace_documents(model, remaining)
        ids.length
      end

      def count(model:, where: nil)
        find_many(model: model, where: where || []).length
      end

      def transaction
        return yield self unless client && @transaction_enabled && client.respond_to?(:start_session)

        session = client.start_session
        begin
          session.start_transaction
          @session = session
          result = yield self
          session.commit_transaction
          result
        rescue
          session.abort_transaction
          raise
        ensure
          @session = nil
          session.end_session
        end
      end

      private

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

      def update_matching(model, where, update, first_only:)
        data = transform_input(model, update, "update", true)
        documents = documents_for(model)
        matches = documents.select { |document| matches_where?(model, document, where) }
        matches = matches.first(1) if first_only
        updates = to_document(model, data)
        ids = matches.map { |document| document["_id"] }
        updated = documents.map do |document|
          ids.include?(document["_id"]) ? document.merge(updates) : document
        end
        replace_documents(model, updated)
        updated.select { |document| ids.include?(document["_id"]) }.map { |document| from_document(model, document) }
      end

      def documents_for(model)
        collection = collection_for(model)
        if collection.respond_to?(:all_documents)
          collection.all_documents
        else
          collection.find({}, session_options).to_a.map { |document| stringify_document(document) }
        end
      end

      def replace_documents(model, documents)
        collection = collection_for(model)
        if collection.respond_to?(:replace_documents)
          collection.replace_documents(documents)
        else
          collection.delete_many({}, session_options)
          documents.each { |document| collection.insert_one(document, session_options) }
        end
      end

      def collection_for(model)
        database.collection(collection_name(model))
      end

      def collection_name(model)
        return schema_for(model).fetch(:model_name) if use_plural

        model.to_s
      end

      def to_document(model, record)
        schema_for(model).fetch(:fields).each_with_object({}) do |(field, attributes), document|
          next unless record.key?(field)

          key = (field == "id") ? "_id" : storage_field(model, field)
          document[key] = store_value(field, record[field], attributes)
        end
      end

      def from_document(model, document)
        fields = schema_for(model).fetch(:fields)
        fields.each_with_object({}) do |(field, attributes), record|
          key = (field == "id") ? "_id" : storage_field(model, field)
          record[field] = output_value(field, fetch_document(document, key), attributes) if document_key?(document, key)
        end
      end

      def stringify_document(document)
        document.each_with_object({}) { |(key, value), result| result[key.to_s] = value }
      end

      def matches_where?(model, document, where)
        clauses = Array(where)
        return true if clauses.empty?

        result = evaluate_clause(model, document, clauses.first)
        clauses.drop(1).each do |clause|
          clause_result = evaluate_clause(model, document, clause)
          if fetch_key(clause, :connector).to_s.upcase == "OR"
            result ||= clause_result
          else
            result &&= clause_result
          end
        end
        result
      end

      def evaluate_clause(model, document, clause)
        field = Schema.storage_key(fetch_key(clause, :field))
        attributes = schema_for(model).fetch(:fields).fetch(field)
        key = (field == "id") ? "_id" : storage_field(model, field)
        expected = store_value(field, fetch_key(clause, :value), attributes)
        current = fetch_document(document, key)
        operator = (fetch_key(clause, :operator) || "eq").to_s

        case operator
        when "in"
          Array(expected).any? { |value| same_value?(current, value) }
        when "not_in"
          Array(expected).none? { |value| same_value?(current, value) }
        when "contains"
          current.to_s.include?(expected.to_s)
        when "starts_with"
          current.to_s.start_with?(expected.to_s)
        when "ends_with"
          current.to_s.end_with?(expected.to_s)
        when "ne"
          !same_value?(current, expected)
        when "gt"
          !expected.nil? && current > expected
        when "gte"
          !expected.nil? && current >= expected
        when "lt"
          !expected.nil? && current < expected
        when "lte"
          !expected.nil? && current <= expected
        else
          same_value?(current, expected)
        end
      end

      def same_value?(left, right)
        left == right || left.to_s == right.to_s
      end

      def apply_join(model, record, join)
        joined = record.dup
        join.each_key do |join_model|
          join_model = join_model.to_s
          joined[join_model] = case [model, join_model]
          when ["session", "user"], ["account", "user"]
            find_one(model: "user", where: [{field: "id", value: record["userId"]}])
          when ["user", "account"]
            find_many(model: "account", where: [{field: "userId", value: record["id"]}])
          end
        end
        joined
      end

      def sort_records(records, sort_by)
        field = Schema.storage_key(fetch_key(sort_by, :field))
        direction = fetch_key(sort_by, :direction).to_s
        records.sort_by { |record| record[field].nil? ? "" : record[field] }.then do |sorted|
          (direction == "desc") ? sorted.reverse : sorted
        end
      end

      def select_fields(record, select, join)
        fields = Array(select).map { |field| Schema.storage_key(field) }
        selected = record.slice(*fields)
        join&.each_key { |join_model| selected[join_model.to_s] = record[join_model.to_s] if record.key?(join_model.to_s) }
        selected
      end

      def store_value(field, value, attributes)
        return nil if value.nil?
        return Array(value).map { |entry| store_value(field, entry, attributes) } if value.is_a?(Array)

        if field == "id" || attributes.dig(:references, :field) == "id"
          return value if custom_id_generator?
          return bson_id(value)
        end

        coerce_value(value, attributes)
      end

      def output_value(field, value, attributes)
        return nil if value.nil?
        return value.to_s if field == "id" || attributes.dig(:references, :field) == "id"

        coerce_value(value, attributes)
      end

      def bson_id(value)
        return value unless defined?(BSON::ObjectId)
        return value if value.is_a?(BSON::ObjectId)

        BSON::ObjectId.from_string(value.to_s)
      rescue
        value
      end

      def generated_id
        generator = options.advanced.dig(:database, :generate_id)
        return generator.call.to_s if generator.respond_to?(:call)
        return SecureRandom.uuid if generator == "uuid"
        return BSON::ObjectId.new.to_s if defined?(BSON::ObjectId)

        SecureRandom.hex(12)
      end

      def custom_id_generator?
        options.advanced.dig(:database, :generate_id).respond_to?(:call)
      end

      def resolve_default(default)
        default.respond_to?(:call) ? default.call : default
      end

      def coerce_value(value, attributes)
        return value if value.nil?
        return Time.parse(value) if attributes[:type] == "date" && value.is_a?(String)

        value
      end

      def session_options
        @session ? {session: @session} : {}
      end

      def document_key?(document, key)
        document.key?(key) || document.key?(key.to_sym)
      end

      def fetch_document(document, key)
        return document[key] if document.key?(key)

        document[key.to_sym]
      end

      def stringify_keys(data)
        data.each_with_object({}) do |(key, value), result|
          result[Schema.storage_key(key)] = value
        end
      end

      def fetch_key(hash, key)
        [key, key.to_s, Schema.storage_key(key), Schema.storage_key(key).to_sym].each do |candidate|
          return hash[candidate] if hash.key?(candidate)
        end
        nil
      end

      def schema_for(model)
        Schema.auth_tables(options).fetch(model.to_s)
      end

      def storage_field(model, field)
        schema_for(model).fetch(:fields).fetch(field.to_s).fetch(:field_name, physical_name(field))
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
