# frozen_string_literal: true

require "rake"
require_relative "../../spec_helper"

class BetterAuthSinatraFakeSQLAdapter < BetterAuth::Adapters::Base
  attr_reader :connection, :dialect

  def initialize(options, connection)
    super(options)
    @connection = connection
    @dialect = :postgres
  end
end

class BetterAuthSinatraFakeSQLConnection
  attr_reader :executed_statements, :applied_versions

  def initialize
    @executed_statements = []
    @applied_versions = []
  end

  def exec(statement)
    @executed_statements << statement

    if statement.match?(/SELECT .*better_auth_schema_migrations/i)
      applied_versions.map { |version| {"version" => version} }
    elsif (match = statement.match(/VALUES \('([^']+)'\)/))
      @applied_versions << match[1]
      []
    else
      []
    end
  end
end

class BetterAuthSinatraFakeQueryConnection
  attr_reader :queries

  def initialize
    @queries = []
  end

  def query(statement)
    @queries << statement
    []
  end
end

RSpec.describe BetterAuth::Sinatra::Migration do
  after do
    BetterAuth::Sinatra.reset!
  end

  it "renders core SQL migrations including plugin schemas" do
    plugin = BetterAuth::Plugin.new(
      id: "api-key-test",
      schema: {
        apiKey: {
          model_name: "api_keys",
          fields: {
            id: {type: "string", required: true},
            userId: {type: "string", required: true, references: {model: "user", field: "id"}, index: true},
            key: {type: "string", required: true, unique: true}
          }
        }
      }
    )
    config = BetterAuth::Configuration.new(secret: secret, database: :memory, plugins: [plugin])

    sql = described_class.render(config, dialect: :postgres)

    expect(sql).to include('CREATE TABLE IF NOT EXISTS "users"')
    expect(sql).to include('CREATE TABLE IF NOT EXISTS "api_keys"')
    expect(sql).to include('CREATE INDEX IF NOT EXISTS "index_api_keys_on_user_id"')
  end

  it "rejects migration execution for adapters without SQL dialect support" do
    auth = BetterAuth.auth(secret: secret, database: :memory)

    expect {
      described_class.migrate(auth, migrations_path: "db/better_auth/migrate")
    }.to raise_error(BetterAuth::Sinatra::Migration::UnsupportedAdapterError, /SQL adapters/)
  end

  it "executes every statement in pending SQL migrations only once" do
    Dir.mktmpdir("better-auth-sinatra-migrate") do |dir|
      migrations_path = File.join(dir, "db/better_auth/migrate")
      FileUtils.mkdir_p(migrations_path)
      File.write(
        File.join(migrations_path, "20260427000000_create_better_auth_tables.sql"),
        "CREATE TABLE users (id text PRIMARY KEY);\nCREATE INDEX index_users_on_email ON users (email);\n"
      )
      connection = BetterAuthSinatraFakeSQLConnection.new
      auth = BetterAuth.auth(
        secret: secret,
        database: ->(options) { BetterAuthSinatraFakeSQLAdapter.new(options, connection) }
      )

      described_class.migrate(auth, migrations_path: migrations_path)
      described_class.migrate(auth, migrations_path: migrations_path)

      expect(connection.executed_statements.count("CREATE TABLE users (id text PRIMARY KEY)")).to eq(1)
      expect(connection.executed_statements.count("CREATE INDEX index_users_on_email ON users (email)")).to eq(1)
      expect(connection.applied_versions).to eq(["20260427000000_create_better_auth_tables.sql"])
    end
  end

  it "supports SQL connections that expose query instead of exec or execute" do
    connection = BetterAuthSinatraFakeQueryConnection.new

    described_class.execute_sql(connection, "CREATE TABLE users (id text PRIMARY KEY);")

    expect(connection.queries).to eq(["CREATE TABLE users (id text PRIMARY KEY)"])
  end

  it "installs config and generates a SQL migration through Rake tasks" do
    Dir.mktmpdir("better-auth-sinatra-tasks") do |dir|
      in_directory(dir) do
        load_tasks

        Rake::Task["better_auth:install"].invoke
        Rake::Task["better_auth:generate:migration"].invoke

        expect(File.read("config/better_auth.rb")).to include("BetterAuth::Sinatra.configure")
        migrations = Dir["db/better_auth/migrate/*_create_better_auth_tables.sql"]
        expect(migrations.length).to eq(1)
        expect(File.read(migrations.first)).to include("CREATE TABLE")
      end
    end
  ensure
    Rake.application = Rake::Application.new
  end

  it "uses BETTER_AUTH_DATABASE_DIALECT when generating migrations" do
    with_env("BETTER_AUTH_DIALECT" => nil, "BETTER_AUTH_DATABASE_DIALECT" => "sqlite") do
      Dir.mktmpdir("better-auth-sinatra-tasks") do |dir|
        in_directory(dir) do
          load_tasks

          Rake::Task["better_auth:generate:migration"].invoke

          migration = Dir["db/better_auth/migrate/*_create_better_auth_tables.sql"].first
          expect(File.read(migration)).to include("-- Dialect: sqlite")
        end
      end
    end
  ensure
    Rake.application = Rake::Application.new
  end

  it "normalizes common database dialect aliases when generating migrations" do
    with_env("BETTER_AUTH_DIALECT" => "postgresql", "BETTER_AUTH_DATABASE_DIALECT" => nil) do
      Dir.mktmpdir("better-auth-sinatra-tasks") do |dir|
        in_directory(dir) do
          load_tasks

          Rake::Task["better_auth:generate:migration"].invoke

          migration = Dir["db/better_auth/migrate/*_create_better_auth_tables.sql"].first
          expect(File.read(migration)).to include("-- Dialect: postgres")
        end
      end
    end
  ensure
    Rake.application = Rake::Application.new
  end

  def secret
    "sinatra-secret-that-is-long-enough-for-validation"
  end

  def in_directory(path)
    previous = Dir.pwd
    Dir.chdir(path)
    yield
  ensure
    Dir.chdir(previous)
  end

  def load_tasks
    Rake.application = Rake::Application.new
    load File.expand_path("../../../lib/better_auth/sinatra/tasks.rb", __dir__)
  end

  def with_env(values)
    previous = values.transform_values { |_value| nil }
    values.each do |key, value|
      previous[key] = ENV[key]
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end
    yield
  ensure
    previous.each do |key, value|
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end
  end
end
