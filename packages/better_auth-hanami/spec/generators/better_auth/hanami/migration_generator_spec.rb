# frozen_string_literal: true

require_relative "../../../spec_helper"

RSpec.describe BetterAuth::Hanami::Generators::MigrationGenerator do
  around do |example|
    Dir.mktmpdir("better-auth-hanami-migration-generator") do |dir|
      @destination = dir
      example.run
    end
  ensure
    BetterAuth::Hanami.instance_variable_set(:@auth, nil)
    BetterAuth::Hanami.instance_variable_set(:@configuration, nil)
  end

  it "creates the Better Auth base migration" do
    described_class.new(destination_root: @destination).run

    migrations = Dir[File.join(@destination, "config/db/migrate/*_create_better_auth_tables.rb")]

    expect(migrations.length).to eq(1)
    expect(File.read(migrations.first)).to include("ROM::SQL.migration")
    expect(File.read(migrations.first)).to include("create_table :users")
  end

  it "does not create a duplicate base migration" do
    path = File.join(@destination, "config/db/migrate")
    FileUtils.mkdir_p(path)
    File.write(File.join(path, "20260427000000_create_better_auth_tables.rb"), "# existing\n")

    described_class.new(destination_root: @destination).run

    migrations = Dir[File.join(@destination, "config/db/migrate/*_create_better_auth_tables.rb")]
    expect(migrations.length).to eq(1)
    expect(File.read(migrations.first)).to eq("# existing\n")
  end

  it "creates migrations with plugin schemas configured through BetterAuth::Hanami" do
    BetterAuth::Hanami.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
      config.plugins = [
        BetterAuth::Plugin.new(
          id: "audit",
          schema: {
            auditLog: {
              model_name: "audit_logs",
              fields: {
                id: {type: "string", required: true},
                action: {type: "string", required: true, unique: true}
              }
            }
          }
        )
      ]
    end

    described_class.new(destination_root: @destination).run

    migration = Dir[File.join(@destination, "config/db/migrate/*_create_better_auth_tables.rb")].first
    expect(File.read(migration)).to include("create_table :audit_logs")
    expect(File.read(migration)).to include("index :action, unique: true")
  end
end
