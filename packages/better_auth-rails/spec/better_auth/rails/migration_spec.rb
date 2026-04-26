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
end
