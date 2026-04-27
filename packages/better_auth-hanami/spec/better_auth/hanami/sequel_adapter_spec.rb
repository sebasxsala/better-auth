# frozen_string_literal: true

require_relative "../../spec_helper"

RSpec.describe BetterAuth::Hanami::SequelAdapter do
  let(:secret) { "test-secret-that-is-long-enough-for-validation" }
  let(:config) { BetterAuth::Configuration.new(secret: secret, database: :memory, plugins: [plugin], experimental: {joins: true}) }
  let(:plugin) do
    BetterAuth::Plugin.new(
      id: "audit",
      schema: {
        auditLog: {
          model_name: "audit_logs",
          fields: {
            id: {type: "string", required: true},
            userId: {type: "string", references: {model: "user", field: "id", on_delete: "cascade"}, index: true},
            action: {type: "string", required: true, unique: true},
            attempts: {type: "number", required: true, default_value: 0},
            createdAt: {type: "date", required: true, default_value: -> { Time.now }}
          }
        }
      }
    )
  end

  it "creates, queries, updates, joins, and deletes records using logical Better Auth fields" do
    db = Sequel.sqlite
    apply_migration(db, config)
    adapter = described_class.new(config, connection: db)

    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    session = adapter.create(model: "session", data: {id: "session-1", userId: "user-1", token: "token-1", expiresAt: Time.now + 3600}, force_allow_id: true)
    adapter.create(model: "auditLog", data: {id: "audit-1", userId: "user-1", action: "login"}, force_allow_id: true)
    adapter.create(model: "auditLog", data: {id: "audit-2", userId: "user-1", action: "logout", attempts: 2}, force_allow_id: true)

    selected = adapter.find_many(model: "auditLog", where: [{field: "action", operator: "contains", value: "log"}], select: ["id", "action"], sort_by: {field: "action", direction: "desc"}, limit: 1)
    joined = adapter.find_one(model: "session", where: [{field: "id", value: session.fetch("id")}], join: {user: true})
    updated = adapter.update_many(model: "auditLog", where: [{field: "userId", value: "user-1"}], update: {attempts: 3}, returning: true)
    count = adapter.count(model: "auditLog", where: [{field: "attempts", operator: "gte", value: 3}])
    adapter.delete(model: "auditLog", where: [{field: "id", value: "audit-1"}])

    expect(user).to include("id" => "user-1", "emailVerified" => false)
    expect(selected).to eq([{"id" => "audit-2", "action" => "logout"}])
    expect(joined.fetch("user")).to include("id" => "user-1", "email" => "ada@example.com")
    expect(updated.map { |row| row.fetch("attempts") }).to eq([3, 3])
    expect(count).to eq(2)
    expect(adapter.find_one(model: "auditLog", where: [{field: "id", value: "audit-1"}])).to be_nil
  end

  # rubocop:disable Security/Eval
  def apply_migration(db, config)
    require "rom-sql"
    gateway = ROM::SQL::Gateway.new(db)
    migration = ROM::SQL.with_gateway(gateway) do
      eval(BetterAuth::Hanami::Migration.render(config), binding, __FILE__, __LINE__)
    end
    migration.apply(db, :up)
  end
  # rubocop:enable Security/Eval
end
