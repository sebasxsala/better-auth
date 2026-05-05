# frozen_string_literal: true

require_relative "../../spec_helper"

class BetterAuthRailsFakeRelation
  include Enumerable

  attr_reader :records
  attr_reader :where_calls
  attr_reader :update_all_calls
  attr_reader :delete_all_calls

  def initialize(records, where_calls = [])
    @records = records
    @where_calls = where_calls
    @update_all_calls = []
    @delete_all_calls = 0
  end

  def where(*args)
    where_calls << args
    self
  end

  def order(*)
    self
  end

  def limit(*)
    self
  end

  def offset(*)
    self
  end

  def select(*)
    self
  end

  def first
    records.first
  end

  def each(&block)
    records.each(&block)
  end

  def count
    records.length
  end

  def update_all(*args)
    update_all_calls << args.first
    records.length
  end

  def delete_all
    @delete_all_calls += 1
    records.length
  end
end

class BetterAuthRailsFakeRecord
  attr_reader :attributes

  def initialize(attributes)
    @attributes = attributes
  end

  def update!(attributes)
    @attributes = @attributes.merge(attributes)
  end

  def destroy!
    true
  end
end

class BetterAuthRailsFakeModel
  class << self
    attr_accessor :created_records, :relation

    def table_name=(_value)
    end

    def primary_key=(_value)
    end

    def create!(attributes)
      record = BetterAuthRailsFakeRecord.new(attributes)
      self.created_records ||= []
      created_records << record
      record
    end

    def all
      relation || BetterAuthRailsFakeRelation.new([])
    end

    def where(*)
      all
    end
  end
end

RSpec.describe BetterAuth::Rails::ActiveRecordAdapter do
  let(:secret) { "test-secret-that-is-long-enough-for-validation" }
  let(:config) { BetterAuth::Configuration.new(secret: secret, database: :memory) }
  let(:adapter) { described_class.new(config, connection: connection) }
  let(:connection) { class_double("ActiveRecord::Base", connection: fake_connection) }
  let(:fake_connection) { instance_double("Connection", transaction: nil) }

  before do
    stub_const("BetterAuth::Rails::ActiveRecordAdapter::ApplicationRecord", BetterAuthRailsFakeModel)
    BetterAuthRailsFakeModel.created_records = []
    BetterAuthRailsFakeModel.relation = BetterAuthRailsFakeRelation.new(
      [BetterAuthRailsFakeRecord.new("id" => "user-1", "email" => "ada@example.com", "email_verified" => false)]
    )
  end

  it "creates records with physical column names and returns logical Better Auth fields" do
    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    created = adapter.send(:model_class, "user").created_records.first

    expect(created.attributes).to include("email_verified" => false)
    expect(user).to include("id" => "user-1", "email" => "ada@example.com", "emailVerified" => false)
  end

  it "preserves false where values for boolean predicates" do
    relation = BetterAuthRailsFakeRelation.new([])
    adapter.send(:model_class, "user").relation = relation

    adapter.find_many(model: "user", where: [{"field" => "emailVerified", "value" => false}])

    expect(relation.where_calls).to include([{"email_verified" => false}])
  end

  it "escapes LIKE wildcards in contains predicates" do
    relation = BetterAuthRailsFakeRelation.new([])
    adapter.send(:model_class, "user").relation = relation

    adapter.find_many(model: "user", where: [{field: "email", operator: "contains", value: "a%_b"}])

    expect(relation.where_calls).to include(["email LIKE ? ESCAPE ?", "%a\\%\\_b%", "\\"])
  end

  it "updates every row matching a predicate and returns the first matched row" do
    relation = BetterAuthRailsFakeRelation.new(
      [
        BetterAuthRailsFakeRecord.new("id" => "user-1", "email" => "ada@example.com", "email_verified" => false),
        BetterAuthRailsFakeRecord.new("id" => "user-2", "email" => "ada@example.com", "email_verified" => false)
      ]
    )
    adapter.send(:model_class, "user").relation = relation

    updated = adapter.update(model: "user", where: [{field: "email", value: "ada@example.com"}], update: {name: "Ada"})

    expect(updated).to include("id" => "user-1")
    expect(relation.update_all_calls).to include(a_hash_including("name" => "Ada"))
  end

  it "deletes every row matching a predicate" do
    relation = BetterAuthRailsFakeRelation.new(
      [
        BetterAuthRailsFakeRecord.new("id" => "user-1", "email" => "ada@example.com", "email_verified" => false),
        BetterAuthRailsFakeRecord.new("id" => "user-2", "email" => "ada@example.com", "email_verified" => false)
      ]
    )
    adapter.send(:model_class, "user").relation = relation

    adapter.delete(model: "user", where: [{field: "email", value: "ada@example.com"}])

    expect(relation.delete_all_calls).to eq(1)
  end

  it "honors custom generated IDs from advanced database options" do
    generated_config = BetterAuth::Configuration.new(
      secret: secret,
      database: :memory,
      advanced: {database: {generate_id: -> { "fixed-id" }}}
    )
    generated_adapter = described_class.new(generated_config, connection: connection)
    generated_adapter.send(:model_class, "user").relation = BetterAuthRailsFakeRelation.new([])

    user = generated_adapter.create(model: "user", data: {name: "Ada", email: "ada@example.com"})

    expect(user.fetch("id")).to eq("fixed-id")
  end

  it "honors uuid generated IDs from advanced database options" do
    generated_config = BetterAuth::Configuration.new(
      secret: secret,
      database: :memory,
      advanced: {database: {generate_id: "uuid"}}
    )
    generated_adapter = described_class.new(generated_config, connection: connection)
    generated_adapter.send(:model_class, "user").relation = BetterAuthRailsFakeRelation.new([])

    user = generated_adapter.create(model: "user", data: {name: "Ada", email: "ada@example.com"})

    expect(user.fetch("id")).to match(/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/)
  end

  it "wraps work in an ActiveRecord transaction" do
    expect(fake_connection).to receive(:transaction).and_yield

    result = adapter.transaction { :ok }

    expect(result).to eq(:ok)
  end
end
