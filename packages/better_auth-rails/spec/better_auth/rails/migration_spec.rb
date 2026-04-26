# frozen_string_literal: true

require_relative "../../spec_helper"

RSpec.describe BetterAuth::Rails::Migration do
  let(:config) { BetterAuth::Configuration.new(secret: "test-secret-that-is-long-enough-for-validation", database: :memory) }

  it "renders a Rails migration from the core Better Auth schema" do
    migration = described_class.render(config)

    expect(migration).to include("class CreateBetterAuthTables < ActiveRecord::Migration")
    expect(migration).to include("create_table :users, id: false")
    expect(migration).to include("t.string :id, null: false")
    expect(migration).to include("ALTER TABLE \#{quote_table_name(:users)} ADD PRIMARY KEY")
    expect(migration).to include("t.boolean :email_verified, null: false, default: false")
    expect(migration).to include("add_index :users, :email, unique: true")
    expect(migration).to include("add_foreign_key :sessions, :users, column: :user_id, on_delete: :cascade")
  end

  it "renders plugin tables and maps logical foreign-key targets to physical Rails tables" do
    plugin = BetterAuth::Plugin.new(
      id: "audit",
      schema: {
        auditLog: {
          model_name: "audit_logs",
          fields: {
            id: {type: "string", required: true},
            userId: {type: "string", required: false, references: {model: "user", field: "id", on_delete: "cascade"}, index: true},
            action: {type: "string", required: true, unique: true},
            attempts: {type: "number", required: true, default_value: 0},
            createdAt: {type: "date", required: true}
          }
        }
      }
    )
    plugin_config = BetterAuth::Configuration.new(
      secret: "test-secret-that-is-long-enough-for-validation",
      database: :memory,
      plugins: [plugin]
    )

    migration = described_class.render(plugin_config)

    expect(migration).to include("create_table :audit_logs, id: false")
    expect(migration).to include("t.string :user_id")
    expect(migration).to include("t.string :action, null: false")
    expect(migration).to include("t.integer :attempts, null: false, default: 0")
    expect(migration).to include("t.datetime :created_at, null: false")
    expect(migration).to include("add_index :audit_logs, :user_id")
    expect(migration).to include("add_index :audit_logs, :action, unique: true")
    expect(migration).to include("add_foreign_key :audit_logs, :users, column: :user_id, on_delete: :cascade")
  end
end
