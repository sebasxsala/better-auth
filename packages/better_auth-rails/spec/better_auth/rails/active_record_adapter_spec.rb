# frozen_string_literal: true

require_relative "../../spec_helper"

class BetterAuthRailsFakeRelation
  include Enumerable

  attr_reader :records
  attr_reader :where_calls

  def initialize(records, where_calls = [])
    @records = records
    @where_calls = where_calls
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

  def update_all(*)
    records.length
  end

  def delete_all
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

  it "wraps work in an ActiveRecord transaction" do
    expect(fake_connection).to receive(:transaction).and_yield

    result = adapter.transaction { :ok }

    expect(result).to eq(:ok)
  end
end
