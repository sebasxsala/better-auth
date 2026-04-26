# frozen_string_literal: true

require "tmpdir"
require_relative "../../spec_helper"

RSpec.describe "BetterAuth::Rails PostgreSQL integration" do
  let(:url) { ENV.fetch("BETTER_AUTH_POSTGRES_URL", "postgres://user:password@localhost:5432/better_auth") }
  let(:secret) { "test-secret-that-is-long-enough-for-validation" }
  let(:config) { BetterAuth::Configuration.new(secret: secret, database: :memory) }

  before do
    require "pg"
    require "active_record"
    ActiveRecord::Base.establish_connection(url)
    reset_schema
  end

  after do
    reset_schema if ActiveRecord::Base.connected?
    ActiveRecord::Base.connection_pool.disconnect! if ActiveRecord::Base.connected?
  end

  it "creates PostgreSQL tables from the generated Rails migration and reads users through ActiveRecord and SQL adapters" do
    run_generated_migration
    active_record_adapter = BetterAuth::Rails::ActiveRecordAdapter.new(config, connection: ActiveRecord::Base)

    created = active_record_adapter.create(
      model: "user",
      data: {id: "user-1", name: "Ada", email: "ada@example.com"},
      force_allow_id: true
    )
    found_with_active_record = active_record_adapter.find_one(model: "user", where: [{field: "email", value: "ada@example.com"}])
    found_with_sql = with_pg_connection do |connection|
      BetterAuth::Adapters::Postgres.new(config, connection: connection)
        .find_one(model: "user", where: [{field: "id", value: "user-1"}])
    end

    expect(created).to include("id" => "user-1", "emailVerified" => false)
    expect(found_with_active_record).to include("name" => "Ada", "email" => "ada@example.com")
    expect(found_with_sql).to include("id" => "user-1", "email" => "ada@example.com", "emailVerified" => false)
    expect(ActiveRecord::Base.connection.data_source_exists?("users")).to be(true)
    expect(ActiveRecord::Base.connection.indexes("users").any? { |index| index.columns == ["email"] && index.unique }).to be(true)
  end

  def run_generated_migration
    Object.send(:remove_const, :CreateBetterAuthTables) if Object.const_defined?(:CreateBetterAuthTables)
    Dir.mktmpdir("better-auth-migration") do |dir|
      path = File.join(dir, "create_better_auth_tables.rb")
      File.write(path, BetterAuth::Rails::Migration.render(config))
      load path
    end
    CreateBetterAuthTables.migrate(:up)
  end

  def reset_schema
    connection = ActiveRecord::Base.connection
    %w[rate_limits verifications accounts sessions users].each do |table|
      connection.execute(%(DROP TABLE IF EXISTS "#{table}" CASCADE))
    end
  end

  def with_pg_connection
    connection = PG.connect(url)
    yield connection
  ensure
    connection&.close
  end
end
